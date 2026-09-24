# CoreDNS Install Notes — Ubuntu 24.04 (edge-fastdog PoP)

Quick reference for setting up CoreDNS on the public PoP droplet.

## Prerequisites

- Ubuntu 24.04 LTS
- Root or sudo access
- Firewall allows 53/tcp and 53/udp (see AUTH_DNS.md)

## 1. Download CoreDNS

```sh
# Get latest stable (adjust version as needed)
COREDNS_VERSION="1.14.7"
curl -fsSL "https://github.com/coredns/coredns/releases/download/v${COREDNS_VERSION}/coredns_${COREDNS_VERSION}_linux_amd64.tgz" \
  | sudo tar -xz -C /usr/local/bin/
sudo chmod +x /usr/local/bin/coredns
coredns -version
```

## 2. Create coredns user

```sh
sudo useradd -r -s /usr/sbin/nologin -d /etc/coredns coredns
```

## 3. Set up directories

```sh
sudo mkdir -p /etc/coredns/zones
sudo chown -R coredns:coredns /etc/coredns
```

## 4. Copy config from this repo

```sh
# From fastdog-edge repo root
sudo cp deploy/coredns/Corefile /etc/coredns/Corefile
sudo chown coredns:coredns /etc/coredns/Corefile
```

## 5. Export and install zone files

```sh
# Export fastdognetworks.com zone from control plane
npm run export-zones -- fastdognetworks.com | sudo tee /etc/coredns/zones/fastdognetworks.com.zone
sudo chown coredns:coredns /etc/coredns/zones/fastdognetworks.com.zone
```

Or use the sync script:

```sh
sudo ./scripts/sync-coredns.sh
```

## 6. Install systemd unit

```sh
sudo cp deploy/coredns/fastdog-coredns.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## 7. Disable systemd-resolved stub (if listening on 53)

Ubuntu's systemd-resolved often binds 127.0.0.53:53. Check and disable if needed:

```sh
# Check what's using port 53
sudo ss -tulnp | grep ':53'

# If systemd-resolved is listening, disable the stub listener:
sudo mkdir -p /etc/systemd/resolved.conf.d
cat <<EOF | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf
[Resolve]
DNSStubListener=no
EOF
sudo systemctl restart systemd-resolved
```

## 8. Start CoreDNS

```sh
sudo systemctl enable --now fastdog-coredns
sudo systemctl status fastdog-coredns
```

## 9. Verify locally

```sh
dig @127.0.0.1 fastdognetworks.com SOA +short
dig @127.0.0.1 edge.fastdognetworks.com A +short
dig @127.0.0.1 ns1.fastdognetworks.com A +short
```

## Reload after zone changes

```sh
# SIGUSR1 triggers zone reload without restart
sudo systemctl reload fastdog-coredns
# or
sudo kill -SIGUSR1 $(pgrep coredns)
```

## Logs

```sh
journalctl -u fastdog-coredns -f
```

## Health check

```sh
curl -s http://127.0.0.1:8053/health
```
