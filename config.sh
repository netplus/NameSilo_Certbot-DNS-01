#!/usr/bin/env bash
# NameSilo_Certbot-DNS-01 configuration

# NameSilo API key.
APIKEY="YOUR_API_KEY"

# Local temporary directory used to store NameSilo XML API responses.
CACHE="tmp/"
RESPONSE="$CACHE/namesilo_response.xml"

# Legacy wait setting, in minutes. The optimized hook uses this value to derive
# DNS_PROPAGATION_TIMEOUT_SECONDS when the latter is not explicitly configured.
WAITTIME=20

# Optional: explicitly set the registered NameSilo DNS zone.
# Usually this is not needed when CERTBOT_DOMAIN is the same as the DNS zone,
# e.g. fine666.com. Set it when validating a subdomain while the zone managed
# in NameSilo is the parent domain, e.g. CERTBOT_DOMAIN=dev.example.com and
# NAMESILO_DOMAIN=example.com.
# NAMESILO_DOMAIN="example.com"

# Optional: TXT record TTL used when creating _acme-challenge records.
# RRTTL=3600

# Optional: DNS propagation polling controls.
# The hook returns only after the expected TXT value is visible on all
# authoritative nameservers, or fails after the timeout.
# DNS_PROPAGATION_TIMEOUT_SECONDS=1200
# DNS_POLL_INTERVAL_SECONDS=15

# Optional: curl networking controls for NameSilo API calls.
# CURL_CONNECT_TIMEOUT=10
# CURL_MAX_TIME=60
