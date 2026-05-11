#!/usr/bin/env bash
# NameSilo_Certbot-DNS-01
# Certbot manual-cleanup-hook for DNS-01 validation via NameSilo DNS.
#
# Certbot calls this script after each DNS-01 challenge. The safest cleanup
# behavior is to delete only the TXT value created for the current challenge.
# This avoids breaking ACME orders that need multiple TXT records under the
# same _acme-challenge host, for example apex + wildcard validations.
#
# NameSilo's API/DNS backend can be eventually consistent. Immediately after a
# successful validation, dnsListRecords may still show the old TXT value even
# though authoritative DNS has already served the new value. Therefore cleanup
# retries dnsListRecords before giving up, instead of reporting "not found" once
# and leaving the new challenge value behind.

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

: "${APIKEY:?APIKEY must be set in config.sh}"
: "${CERTBOT_DOMAIN:?CERTBOT_DOMAIN is not set by Certbot}"
# CERTBOT_VALIDATION should normally be available for cleanup hooks. If it is
# missing, we intentionally do nothing rather than deleting every ACME TXT value.
CERTBOT_VALIDATION="${CERTBOT_VALIDATION:-}"

DOMAIN="${CERTBOT_DOMAIN%.}"
VALIDATION="$CERTBOT_VALIDATION"
BASE_DOMAIN="${NAMESILO_DOMAIN:-$DOMAIN}"
BASE_DOMAIN="${BASE_DOMAIN%.}"

CACHE="${CACHE:-tmp/}"
[[ "$CACHE" != */ ]] && CACHE="${CACHE}/"
RESPONSE="${RESPONSE:-${CACHE}namesilo_response.xml}"
LIST_RESPONSE="${CACHE}${BASE_DOMAIN}.records.xml"

CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-10}"
CURL_MAX_TIME="${CURL_MAX_TIME:-60}"
CLEANUP_LIST_RETRY_COUNT="${CLEANUP_LIST_RETRY_COUNT:-20}"
CLEANUP_LIST_RETRY_INTERVAL_SECONDS="${CLEANUP_LIST_RETRY_INTERVAL_SECONDS:-15}"

mkdir -p "$CACHE" "$(dirname "$RESPONSE")"

# Convert Certbot's domain into the rrhost expected by NameSilo. Keep this in
# sync with hook.sh so cleanup targets the exact FQDN created during auth.
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

  # Use URL-encoded parameters for consistency with hook.sh and to avoid query
  # string breakage if user-provided values contain special characters.
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

record_ids_for_current_validation() {
  # Return the rrid values whose host, type, and TXT value match the current
  # challenge exactly. This leaves stale or concurrent ACME records untouched.
  xmllint --xpath "//namesilo/reply/resource_record[host/text()='${ACME_FQDN}' and type/text()='TXT' and value/text()='${VALIDATION}']/record_id/text()" "$LIST_RESPONSE" 2>/dev/null || true
}

log_current_acme_records_from_api() {
  local records

  # Diagnostic only: print all currently listed _acme-challenge TXT values from
  # NameSilo's API. This helps distinguish "API list is still stale" from
  # "cleanup is computing the wrong host name".
  records="$(xmllint --xpath "//namesilo/reply/resource_record[host/text()='${ACME_FQDN}' and type/text()='TXT']/value/text()" "$LIST_RESPONSE" 2>/dev/null || true)"
  log "NameSilo API currently lists TXT for ${ACME_FQDN}: ${records:-<empty>}"
}

delete_record() {
  local rrid="$1"

  [[ -z "$rrid" ]] && return 0
  log "Deleting TXT record rrid=${rrid}: ${ACME_FQDN} -> ${VALIDATION}"

  namesilo_api "dnsDeleteRecord" "$RESPONSE" \
    --data-urlencode "domain=${BASE_DOMAIN}" \
    --data-urlencode "rrid=${rrid}"

  assert_namesilo_success "$RESPONSE" "dnsDeleteRecord rrid=${rrid}"
}

find_record_ids_with_retry() {
  local attempt ids

  for (( attempt=1; attempt<=CLEANUP_LIST_RETRY_COUNT; attempt++ )); do
    list_records
    log_current_acme_records_from_api

    ids="$(record_ids_for_current_validation | tr '\n' ' ')"
    if [[ -n "${ids// }" ]]; then
      printf '%s\n' $ids
      return 0
    fi

    if (( attempt < CLEANUP_LIST_RETRY_COUNT )); then
      log "Current validation TXT not visible in NameSilo API list yet; cleanup retry ${attempt}/${CLEANUP_LIST_RETRY_COUNT}, sleep ${CLEANUP_LIST_RETRY_INTERVAL_SECONDS}s"
      sleep "$CLEANUP_LIST_RETRY_INTERVAL_SECONDS"
    fi
  done

  return 1
}

log "Received DNS-01 cleanup request for ${DOMAIN}"
log "NameSilo zone=${BASE_DOMAIN}, rrhost=${RRHOST}, fqdn=${ACME_FQDN}"

if [[ -z "$VALIDATION" ]]; then
  log "CERTBOT_VALIDATION is empty; skip cleanup to avoid deleting unrelated TXT records."
  exit 0
fi

mapfile -t RECORD_IDS < <(find_record_ids_with_retry || true)

if (( ${#RECORD_IDS[@]} == 0 )); then
  # Do not fail certificate renewal only because cleanup cannot find a record.
  # The certificate has already been validated at this point. We log a warning
  # so stale TXT records can be cleaned manually if NameSilo never exposes them
  # through dnsListRecords.
  log "WARNING: No TXT record found for current validation value after retries; leaving DNS unchanged."
else
  for rrid in "${RECORD_IDS[@]}"; do
    delete_record "$rrid"
  done
fi

rm -f "$RESPONSE" "$LIST_RESPONSE"
log "Manual cleanup hook completed."
