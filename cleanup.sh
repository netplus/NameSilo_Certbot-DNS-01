#!/usr/bin/env bash
# NameSilo_Certbot-DNS-01
# Certbot manual-cleanup-hook for DNS-01 validation via NameSilo DNS.
#
# Certbot calls this script after each DNS-01 challenge. The safest cleanup
# behavior is to delete only the TXT value created for the current challenge.
# This avoids breaking ACME orders that need multiple TXT records under the
# same _acme-challenge host, for example apex + wildcard validations.

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

delete_record() {
  local rrid="$1"

  [[ -z "$rrid" ]] && return 0
  log "Deleting TXT record rrid=${rrid}: ${ACME_FQDN} -> ${VALIDATION}"

  namesilo_api "dnsDeleteRecord" "$RESPONSE" \
    --data-urlencode "domain=${BASE_DOMAIN}" \
    --data-urlencode "rrid=${rrid}"

  assert_namesilo_success "$RESPONSE" "dnsDeleteRecord rrid=${rrid}"
}

log "Received DNS-01 cleanup request for ${DOMAIN}"
log "NameSilo zone=${BASE_DOMAIN}, rrhost=${RRHOST}, fqdn=${ACME_FQDN}"

if [[ -z "$VALIDATION" ]]; then
  log "CERTBOT_VALIDATION is empty; skip cleanup to avoid deleting unrelated TXT records."
  exit 0
fi

list_records

mapfile -t RECORD_IDS < <(record_ids_for_current_validation)

if (( ${#RECORD_IDS[@]} == 0 )); then
  log "No TXT record found for current validation value; nothing to clean up."
else
  for rrid in "${RECORD_IDS[@]}"; do
    delete_record "$rrid"
  done
fi

rm -f "$RESPONSE" "$LIST_RESPONSE"
log "Manual cleanup hook completed."
