#!/usr/bin/env bash
# NameSilo_Certbot-DNS-01
# Certbot manual-auth-hook for DNS-01 validation via NameSilo DNS.
#
# Certbot calls this script once for each DNS-01 challenge and provides:
#   CERTBOT_DOMAIN      The domain being validated, e.g. fine666.com
#   CERTBOT_VALIDATION  The TXT value that Let's Encrypt must observe
#
# Reliability notes:
#   1. The hook must not return before the TXT record is visible in DNS. Once
#      this script returns, Certbot immediately asks Let's Encrypt to validate.
#   2. We add a fresh TXT record instead of updating an existing one. ACME
#      orders that include both apex and wildcard names may require multiple
#      TXT values under the same _acme-challenge name.
#   3. cleanup.sh removes only the TXT value created for the current challenge
#      by default, so concurrent or multi-name validations are not broken.

set -euo pipefail
IFS=$'\n\t'

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"

# shellcheck source=/dev/null
source "$DIR/config.sh"
cd "$DIR"

log() {
  printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

die() {
  printf '[%s] ERROR: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

require_cmd curl
require_cmd xmllint
require_cmd awk

: "${APIKEY:?APIKEY must be set in config.sh}"
: "${CERTBOT_DOMAIN:?CERTBOT_DOMAIN is not set by Certbot}"
: "${CERTBOT_VALIDATION:?CERTBOT_VALIDATION is not set by Certbot}"

DOMAIN="${CERTBOT_DOMAIN%.}"
VALIDATION="$CERTBOT_VALIDATION"

# NameSilo API requires the registered zone name as the 'domain' parameter.
# For the common case, CERTBOT_DOMAIN is already the registered domain. If you
# validate a subdomain such as *.dev.example.com while the NameSilo zone is
# example.com, set NAMESILO_DOMAIN="example.com" in config.sh.
BASE_DOMAIN="${NAMESILO_DOMAIN:-$DOMAIN}"
BASE_DOMAIN="${BASE_DOMAIN%.}"

CACHE="${CACHE:-tmp/}"
[[ "$CACHE" != */ ]] && CACHE="${CACHE}/"
RESPONSE="${RESPONSE:-${CACHE}namesilo_response.xml}"
LIST_RESPONSE="${CACHE}${BASE_DOMAIN}.records.xml"

RRTTL="${RRTTL:-3600}"
WAITTIME="${WAITTIME:-20}"
DNS_PROPAGATION_TIMEOUT_SECONDS="${DNS_PROPAGATION_TIMEOUT_SECONDS:-$((WAITTIME * 60))}"
DNS_POLL_INTERVAL_SECONDS="${DNS_POLL_INTERVAL_SECONDS:-15}"
CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-10}"
CURL_MAX_TIME="${CURL_MAX_TIME:-60}"

mkdir -p "$CACHE" "$(dirname "$RESPONSE")"

# Convert Certbot's domain into the rrhost expected by NameSilo.
#   CERTBOT_DOMAIN=fine666.com, BASE_DOMAIN=fine666.com
#     => rrhost=_acme-challenge
#   CERTBOT_DOMAIN=dev.example.com, BASE_DOMAIN=example.com
#     => rrhost=_acme-challenge.dev
if [[ "$DOMAIN" == "$BASE_DOMAIN" ]]; then
  RRHOST="_acme-challenge"
elif [[ "$DOMAIN" == *".${BASE_DOMAIN}" ]]; then
  SUBDOMAIN="${DOMAIN%.$BASE_DOMAIN}"
  RRHOST="_acme-challenge.${SUBDOMAIN}"
else
  die "CERTBOT_DOMAIN=$DOMAIN is not equal to or under NAMESILO_DOMAIN=$BASE_DOMAIN"
fi

ACME_FQDN="${RRHOST}.${BASE_DOMAIN}"

namesilo_api() {
  local endpoint="$1"
  local output="$2"
  shift 2

  # Use --data-urlencode instead of hand-built query strings so TXT values and
  # other parameters remain safe if future ACME tokens or settings contain
  # characters that need URL encoding.
  curl -fsS \
    --retry 3 \
    --retry-delay 2 \
    --connect-timeout "$CURL_CONNECT_TIMEOUT" \
    --max-time "$CURL_MAX_TIME" \
    -G "https://www.namesilo.com/api/${endpoint}" \
    --data-urlencode "version=1" \
    --data-urlencode "type=xml" \
    --data-urlencode "key=${APIKEY}" \
    "$@" > "$output"
}

xml_string() {
  local file="$1"
  local xpath="$2"
  xmllint --xpath "string(${xpath})" "$file" 2>/dev/null || true
}

assert_namesilo_success() {
  local file="$1"
  local operation="$2"
  local code detail

  code="$(xml_string "$file" "//namesilo/reply/code")"
  detail="$(xml_string "$file" "//namesilo/reply/detail")"

  if [[ "$code" != "300" ]]; then
    die "NameSilo ${operation} failed: code=${code:-<empty>} detail=${detail:-<empty>}"
  fi

  log "NameSilo ${operation} succeeded: ${detail:-code 300}"
}

list_records() {
  namesilo_api "dnsListRecords" "$LIST_RESPONSE" \
    --data-urlencode "domain=${BASE_DOMAIN}"
  assert_namesilo_success "$LIST_RESPONSE" "dnsListRecords"
}

txt_value_already_exists() {
  local count

  # Check whether this exact validation token is already present. This makes
  # reruns idempotent without touching other TXT values at the same host.
  count="$(xmllint --xpath "count(//namesilo/reply/resource_record[host/text()='${ACME_FQDN}' and type/text()='TXT' and value/text()='${VALIDATION}'])" "$LIST_RESPONSE" 2>/dev/null || echo 0)"
  [[ "$count" != "0" && "$count" != "0.0" ]]
}

add_txt_record() {
  log "Adding TXT record: ${ACME_FQDN} -> ${VALIDATION}"

  namesilo_api "dnsAddRecord" "$RESPONSE" \
    --data-urlencode "domain=${BASE_DOMAIN}" \
    --data-urlencode "rrtype=TXT" \
    --data-urlencode "rrhost=${RRHOST}" \
    --data-urlencode "rrvalue=${VALIDATION}" \
    --data-urlencode "rrttl=${RRTTL}"

  assert_namesilo_success "$RESPONSE" "dnsAddRecord"
}

txt_visible_from_nameserver() {
  local ns="$1"
  local records

  records="$(dig @"$ns" TXT "$ACME_FQDN" +short 2>/dev/null | tr -d '"' || true)"

  if printf '%s\n' "$records" | grep -Fqx "$VALIDATION"; then
    return 0
  fi

  # Keep a substring fallback for resolvers that render long TXT records in a
  # split format. ACME validation values normally fit in one TXT string, so the
  # exact-line check above is the primary path.
  if printf '%s\n' "$records" | grep -Fq "$VALIDATION"; then
    return 0
  fi

  log "TXT not visible on ${ns} yet. Current TXT: ${records:-<empty>}"
  return 1
}

wait_for_dns_propagation() {
  local ns_list deadline attempt missing ns

  # dig is optional at install time, but it gives us deterministic behavior: we
  # wait until the authoritative NameSilo nameservers can actually answer with
  # the expected TXT value. If dig is absent, fall back to the legacy fixed wait.
  if ! command -v dig >/dev/null 2>&1; then
    log "dig is not installed; falling back to fixed wait of ${DNS_PROPAGATION_TIMEOUT_SECONDS}s"
    sleep "$DNS_PROPAGATION_TIMEOUT_SECONDS"
    return 0
  fi

  ns_list="$(dig +short NS "$BASE_DOMAIN" | sed 's/\.$//' | sort -u || true)"
  if [[ -z "$ns_list" ]]; then
    log "Could not discover authoritative NS for ${BASE_DOMAIN}; falling back to fixed wait of ${DNS_PROPAGATION_TIMEOUT_SECONDS}s"
    sleep "$DNS_PROPAGATION_TIMEOUT_SECONDS"
    return 0
  fi

  log "Waiting for DNS propagation: ${ACME_FQDN} TXT, timeout=${DNS_PROPAGATION_TIMEOUT_SECONDS}s, interval=${DNS_POLL_INTERVAL_SECONDS}s"
  log "Authoritative nameservers: $(echo "$ns_list" | tr '\n' ' ')"

  deadline=$((SECONDS + DNS_PROPAGATION_TIMEOUT_SECONDS))
  attempt=1

  while (( SECONDS <= deadline )); do
    missing=0

    while IFS= read -r ns; do
      [[ -z "$ns" ]] && continue
      if txt_visible_from_nameserver "$ns"; then
        log "TXT is visible on ${ns}"
      else
        missing=1
      fi
    done <<< "$ns_list"

    if (( missing == 0 )); then
      log "DNS propagation confirmed on all authoritative nameservers."
      return 0
    fi

    if (( SECONDS >= deadline )); then
      break
    fi

    log "DNS propagation not complete; retry ${attempt} after ${DNS_POLL_INTERVAL_SECONDS}s"
    sleep "$DNS_POLL_INTERVAL_SECONDS"
    attempt=$((attempt + 1))
  done

  die "TXT record ${ACME_FQDN} did not propagate within ${DNS_PROPAGATION_TIMEOUT_SECONDS}s"
}

log "Received DNS-01 challenge request for ${DOMAIN}"
log "NameSilo zone=${BASE_DOMAIN}, rrhost=${RRHOST}, fqdn=${ACME_FQDN}"

list_records

if txt_value_already_exists; then
  log "TXT value already exists; skip adding duplicate record."
else
  add_txt_record
fi

wait_for_dns_propagation

log "Manual auth hook completed. Certbot can now trigger ACME validation."
