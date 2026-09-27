#!/usr/bin/env bash
set -u -o pipefail

domain="${1:-fastdognetworks.com}"
ns1=157.230.57.32
ns2=2.29.58.90
safe=yes

echo "NS-cut checklist for $domain"
echo 'HOLD — do not flip registrar NS from this tool; checklist only.'

if [[ ! "$domain" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo 'FAIL invalid domain'
  echo 'SAFE_TO_FLIP=no'
  exit 1
fi
if ! command -v dig >/dev/null 2>&1; then
  echo 'FAIL dig is unavailable'
  echo 'SAFE_TO_FLIP=no'
  exit 1
fi

query() {
  dig +short +time=2 +tries=1 "@$1" "$2" "$3" 2>/dev/null | sed '/^[[:space:]]*$/d' | LC_ALL=C sort
}

check() {
  local label="$1" host="$2" type="$3" pattern="$4" left right
  left="$(query "$ns1" "$host" "$type")"
  right="$(query "$ns2" "$host" "$type")"
  if [[ -z "$left" || -z "$right" ]]; then
    echo "FAIL $label: missing answer from one or both PoPs"
    safe=no
  elif [[ "$left" != "$right" ]]; then
    echo "FAIL $label: ns1/ns2 mismatch"
    safe=no
  elif [[ ! "$left" =~ $pattern ]]; then
    echo "FAIL $label: required record absent or unexpected"
    safe=no
  else
    echo "PASS $label: ns1/ns2 match; expected value present"
  fi
}

check MX "$domain" MX '(^|[[:space:]])chocobo\.mxrouting\.net\.'
check SPF "$domain" TXT 'v=spf1[[:space:]]+include:mxroute\.com'
check DMARC "_dmarc.$domain" TXT 'v=DMARC1;[[:space:]]*p=none'
check DKIM "x._domainkey.$domain" TXT 'v=DKIM1;.*p=[A-Za-z0-9+/]+'

soa1="$(query "$ns1" "$domain" SOA)"
soa2="$(query "$ns2" "$domain" SOA)"
serial1="$(awk '{print $3}' <<< "$soa1")"
serial2="$(awk '{print $3}' <<< "$soa2")"
if [[ -n "$serial1" && "$serial1" =~ ^[0-9]+$ && "$serial1" == "$serial2" ]]; then
  echo "PASS SOA serial: ns1/ns2 match ($serial1)"
else
  echo "FAIL SOA serial: missing or ns1/ns2 mismatch ($serial1 / $serial2)"
  safe=no
fi

echo "SAFE_TO_FLIP=$safe"
[[ "$safe" == yes ]]
