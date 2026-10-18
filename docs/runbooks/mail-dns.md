# Mail DNS check (read-only)

`scripts/mail-dns-check.js` (wrapper `scripts/check-mail-dns.sh`) runs `dig +short +time=3 +tries=1` for MX, SPF, DKIM and DMARC and prints one `PASS`/`WARN`/`FAIL` line per check and resolver. It never changes DNS. Run it only inside an operator-authorized online window, since it makes live DNS queries; tests use canned output and no network.

```sh
bash scripts/check-mail-dns.sh example.test                      # system resolver only
bash scripts/check-mail-dns.sh example.test 192.0.2.53 198.51.100.53 --selector x
node scripts/mail-dns-check.js example.test --server 192.0.2.53 --expect include:mail.provider.example
```

- Positional arguments after the domain and each `--server` are checked first, then the system resolver. Use both authoritative nameservers plus one public resolver to catch split answers.
- `--selector` is the DKIM selector (default `x`, no trailing dot). Use the one your provider shows in its DNS panel.
- `--expect` (repeatable) is the SPF include or mechanism your provider requires; a bare host means `include:<host>`. SPF is `FAIL` unless at least one is pass-qualified (no qualifier or `+`) and appears before the first `all`; `-include:x`, `~include:x` or anything after `all` does not authorize the sender. An expected `redirect=` only counts when the record has no `all`.
- The domain, servers and selector must be plain hostnames or IP addresses; anything else exits 1 before dig runs. A missing `dig` also exits 1. Otherwise the exit code is 0, including when checks fail. Read the lines.

## Records a hosted mail provider needs

Copy exact values from the provider's control panel; the names below are placeholders.

| Record | Name | Value shape | Checker result |
| --- | --- | --- | --- |
| MX | `@` | `10 mx1.provider.example.` (plus any backup MX with a higher number) | FAIL if none or null MX `0 .` |
| SPF (TXT) | `@` | `v=spf1 include:<provider spf host> -all` | Exactly one `v=spf1` record. WARN for `~all`/`?all`/`+all`, a missing `all`, or multiple SPF records |
| DKIM (TXT) | `<selector>._domainkey` | `v=DKIM1; k=rsa; p=<base64 public key>` | FAIL if no record, empty `p=` (revoked), invalid base64, a key Node cannot parse as RSA (SPKI or PKCS#1), an RSA key under 1024 bits, an `ed25519` key that is not 32 bytes, or any other `k=`. 2048-bit RSA recommended |
| DMARC (TXT) | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:<reports address>` | WARN for `p=none` (monitor only) or missing `rua=`; FAIL if `p=` is missing or invalid |

Notes:
- Merge every sender (provider, billing mailer, etc.) into one SPF record; two `v=spf1` records break SPF for all of them. Stay under SPF's 10-DNS-lookup limit (this tool does not count lookups).
- Long DKIM keys are split into several quoted strings in one TXT record. The checker joins them, as receivers do.
- Start DMARC at `p=none` with `rua=` while you confirm alignment, then move to `quarantine` or `reject`.
- Record changes follow [DNS changes](dns-changes.md) (backup, serial bump, both nameservers). After that, run this check against each nameserver and confirm they agree.
