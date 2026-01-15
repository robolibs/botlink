# Botlink Deployment Guide

This guide covers deploying Botlink in production environments.

## Prerequisites

### System Requirements

- Linux kernel 3.10+ with TUN/TAP support
- libsodium 1.0.18+
- CMake 3.16+ or xmake
- C++20 compatible compiler (GCC 10+, Clang 12+)

### Required Capabilities

Botlink requires elevated privileges for TUN device creation:

```bash
# Option 1: Run as root (not recommended for production)
sudo ./botlink-node

# Option 2: Set capabilities (recommended)
sudo setcap cap_net_admin=eip ./botlink-node
```

## Building from Source

### Using CMake

```bash
git clone https://github.com/your-org/botlink.git
cd botlink

mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_EXAMPLES=ON
make -j$(nproc)
```

### Using xmake

```bash
git clone https://github.com/your-org/botlink.git
cd botlink

xmake config -m release
xmake build
```

## Configuration

### Configuration File Format

Botlink uses TOML configuration files. Create `/etc/botlink/config.toml`:

```toml
[node]
name = "node-alpha"
role = "member"

[node.overlay]
addr = "10.42.0.1/24"
listen = ["0.0.0.0:51820"]
mtu = 1420

[identity]
# Base64-encoded keys (generate with botlink-keygen)
ed25519_private = "base64-encoded-key..."
ed25519_public = "base64-encoded-key..."
x25519_private = "base64-encoded-key..."
x25519_public = "base64-encoded-key..."

[trust]
chain_path = "/var/lib/botlink/chain.dat"

[trust.policy]
min_yes_votes = 2
vote_timeout_ms = 86400000  # 24 hours

[[trust.bootstraps]]
id = "bootstrap-1"
type = "member"
endpoint = "udp://bootstrap.example.com:51820"
pubkey = "base64-encoded-pubkey..."
```

### Key Generation

Generate keypairs for a new node:

```bash
# Generate Ed25519 signing keypair
./botlink-keygen ed25519 > ed25519.keys

# Generate X25519 key exchange keypair
./botlink-keygen x25519 > x25519.keys
```

## Systemd Service

Create `/etc/systemd/system/botlink.service`:

```ini
[Unit]
Description=Botlink Decentralized VPN
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/botlink-node -c /etc/botlink/config.toml
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/botlink
PrivateTmp=yes
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable botlink
sudo systemctl start botlink
```

## Firewall Configuration

### UFW (Ubuntu/Debian)

```bash
# Allow Botlink UDP port
sudo ufw allow 51820/udp

# Allow traffic on overlay network
sudo ufw allow in on botlink0
```

### iptables

```bash
# Allow Botlink UDP traffic
iptables -A INPUT -p udp --dport 51820 -j ACCEPT

# Allow forwarding for overlay network
iptables -A FORWARD -i botlink0 -j ACCEPT
iptables -A FORWARD -o botlink0 -j ACCEPT

# NAT for outbound traffic (if needed)
iptables -t nat -A POSTROUTING -s 10.42.0.0/24 -o eth0 -j MASQUERADE
```

### firewalld (RHEL/CentOS)

```bash
# Create Botlink zone
firewall-cmd --permanent --new-zone=botlink
firewall-cmd --permanent --zone=botlink --add-port=51820/udp
firewall-cmd --permanent --zone=botlink --add-interface=botlink0
firewall-cmd --reload
```

## Network Topology

### Star Topology (Simple)

```
      [Bootstrap/Founder]
         /    |    \
        /     |     \
    [Node1] [Node2] [Node3]
```

All nodes connect to a bootstrap node that maintains the trust chain.

### Mesh Topology (Resilient)

```
    [Node1] --- [Node2]
       |    X     |
       |   / \    |
    [Node3] --- [Node4]
```

Nodes maintain connections to multiple peers for redundancy.

## Multi-Node Deployment

### Node 1 (Founder/Genesis)

```toml
[node]
name = "founder"
role = "member"

[node.overlay]
addr = "10.42.0.1/24"
listen = ["0.0.0.0:51820"]

# No bootstraps - this is the genesis node
```

### Node 2+ (Joining Nodes)

```toml
[node]
name = "node-2"
role = "member"

[node.overlay]
addr = "10.42.0.2/24"
listen = ["0.0.0.0:51820"]

[[trust.bootstraps]]
id = "founder"
type = "member"
endpoint = "udp://founder.example.com:51820"
pubkey = "founder-ed25519-pubkey..."
```

## Health Checks

### Check Node Status

```bash
# View systemd status
systemctl status botlink

# Check TUN interface
ip link show botlink0
ip addr show botlink0

# View routing table
ip route show dev botlink0

# Check listening port
ss -ulnp | grep 51820
```

### Monitoring Metrics

Botlink exposes metrics via the control socket:

```bash
# Get node stats
echo "stats" | nc -U /var/run/botlink.sock

# List connected peers
echo "peers" | nc -U /var/run/botlink.sock
```

## Security Recommendations

1. **Key Management**
   - Store private keys with restricted permissions (600)
   - Use separate keys for each node
   - Rotate keys periodically

2. **Network Isolation**
   - Run Botlink in a dedicated network namespace if possible
   - Use firewall rules to restrict overlay network access

3. **Monitoring**
   - Enable logging to detect anomalies
   - Monitor for replay attacks (logged when detected)
   - Set up alerts for handshake failures

4. **Updates**
   - Keep libsodium updated for security patches
   - Monitor Botlink releases for security fixes

## IPv6 Support

Botlink supports IPv6 for both the underlay (transport) and overlay networks.

### IPv6 Transport

```toml
[node.overlay]
listen = ["[::]:51820"]  # Listen on IPv6

[[trust.bootstraps]]
endpoint = "udp://[2001:db8::1]:51820"  # IPv6 bootstrap
```

### IPv6 Overlay

```toml
[node.overlay]
addr = "fd00:42::1/64"  # ULA prefix for overlay
```

### DNS Resolution

Botlink automatically resolves hostnames to IPv6 addresses when available:

```toml
[[trust.bootstraps]]
endpoint = "udp://bootstrap.example.com:51820"  # Resolves to IPv4 or IPv6
```
