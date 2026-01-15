# Botlink Troubleshooting Guide

This guide helps diagnose and resolve common issues with Botlink.

## Common Errors

### TUN Device Creation Failed

**Error:** `Failed to create TUN device: Operation not permitted`

**Cause:** Missing CAP_NET_ADMIN capability or running without root.

**Solution:**
```bash
# Option 1: Set capabilities
sudo setcap cap_net_admin=eip ./botlink-node

# Option 2: Run with sudo (not recommended for production)
sudo ./botlink-node -c config.toml
```

### Handshake Timeout

**Error:** `Handshake timed out for peer <node-id>`

**Causes:**
1. Firewall blocking UDP port
2. NAT traversal failure
3. Peer not running or unreachable
4. Clock skew between nodes

**Diagnosis:**
```bash
# Check if port is open
sudo ss -ulnp | grep 51820

# Test UDP connectivity
nc -u -v <peer-ip> 51820

# Check firewall
sudo iptables -L -n | grep 51820
```

**Solutions:**
```bash
# Open firewall port
sudo ufw allow 51820/udp

# Check peer is running
ssh peer-host "systemctl status botlink"

# Sync system time
sudo timedatectl set-ntp true
```

### Peer Not Trusted

**Error:** `Peer is not an approved member`

**Cause:** The peer's public key is not in the local trust chain.

**Diagnosis:**
```bash
# Check trust chain members
echo "members" | nc -U /var/run/botlink.sock
```

**Solution:**
1. Ensure the peer has completed the join flow
2. Sync trust chain from other members
3. Wait for proposal to be approved

### Replay Attack Detected

**Error:** `Replay detected - packet rejected`

**Cause:** Duplicate packet received (either network issue or actual attack).

**Diagnosis:**
This is usually benign and caused by:
- Network retransmissions
- Packet duplication by routers

**Solution:**
- If frequent, check for network issues
- If persistent from one peer, investigate that peer

### DNS Resolution Failed

**Error:** `DNS resolution failed: Name or service not known`

**Causes:**
1. Invalid hostname
2. DNS server unreachable
3. Network configuration issue

**Diagnosis:**
```bash
# Test DNS resolution
host bootstrap.example.com

# Check DNS configuration
cat /etc/resolv.conf

# Test with specific DNS server
dig @8.8.8.8 bootstrap.example.com
```

**Solution:**
```bash
# Use IP address directly as fallback
endpoint = "udp://192.168.1.100:51820"

# Or fix DNS configuration
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

### Session Key Mismatch

**Error:** `Key ID mismatch` or `AEAD decryption failed`

**Cause:** Keys have desynchronized between peers, often after rekey.

**Solution:**
1. Both peers should re-handshake
2. Restart one or both nodes
3. Check for clock synchronization issues

## Debug Logging

### Enable Verbose Logging

Set environment variable before starting:
```bash
export BOTLINK_LOG_LEVEL=debug
./botlink-node -c config.toml
```

Or in systemd service:
```ini
[Service]
Environment="BOTLINK_LOG_LEVEL=debug"
```

### Log Output Locations

- **Systemd:** `journalctl -u botlink -f`
- **Direct run:** stderr (redirect with `2> botlink.log`)

### Key Log Messages

| Message | Meaning |
|---------|---------|
| `Handshake complete as initiator` | Successfully connected to peer |
| `Handshake complete as responder` | Peer successfully connected to us |
| `Replay detected` | Duplicate packet blocked |
| `Chain sync complete` | Trust chain synchronized |
| `Rekey complete` | Session keys rotated |

## Network Debugging

### Check TUN Interface

```bash
# Interface exists and is up
ip link show botlink0

# Expected output:
# botlink0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 ...

# Check IP address
ip addr show botlink0

# Check routing
ip route show dev botlink0
```

### Check UDP Socket

```bash
# Verify listening
ss -ulnp | grep 51820

# Check for errors
netstat -su
```

### Packet Capture

```bash
# Capture Botlink traffic
sudo tcpdump -i eth0 udp port 51820 -w botlink.pcap

# Capture TUN traffic
sudo tcpdump -i botlink0 -w tunnel.pcap
```

### Test Connectivity

```bash
# Ping through overlay
ping 10.42.0.2

# Check latency
mtr 10.42.0.2

# Test TCP over overlay
nc -zv 10.42.0.2 22
```

## Peer Connection Issues

### NAT Traversal

Botlink uses UDP hole punching for NAT traversal. If connections fail:

1. **Symmetric NAT:** May require a relay node
2. **Strict firewall:** Configure port forwarding
3. **Carrier-grade NAT:** Use IPv6 if available

```bash
# Check NAT type
stun stun.l.google.com:19302
```

### Relay Mode

If direct connection fails, configure a relay:

```toml
[[trust.bootstraps]]
id = "relay-1"
type = "relay"
endpoint = "udp://relay.example.com:51820"
pubkey = "relay-pubkey..."
```

## Trust Chain Issues

### Chain Sync Failed

**Error:** `Failed to sync trust chain`

**Causes:**
1. No connected peers with newer chain
2. Network partition
3. Invalid chain data

**Solution:**
```bash
# Force resync from specific peer
echo "sync <peer-id>" | nc -U /var/run/botlink.sock

# Reset chain (WARNING: loses local votes)
rm /var/lib/botlink/chain.dat
systemctl restart botlink
```

### Voting Timeout

**Error:** `Proposal expired without decision`

**Cause:** Not enough votes received within timeout period.

**Solution:**
1. Ensure enough members are online
2. Increase `vote_timeout_ms` in configuration
3. Re-submit the proposal

## Performance Issues

### High Latency

**Causes:**
1. Geographically distant peers
2. Congested network
3. CPU-bound encryption

**Diagnosis:**
```bash
# Check CPU usage
top -p $(pgrep botlink)

# Check network latency
mtr <peer-ip>
```

**Solutions:**
- Use geographically closer peers
- Optimize MTU settings
- Ensure hardware AES support

### Packet Loss

**Causes:**
1. Network congestion
2. MTU issues (fragmentation)
3. Buffer overflow

**Diagnosis:**
```bash
# Check interface errors
ip -s link show botlink0

# Check for fragmentation
ping -M do -s 1400 10.42.0.2
```

**Solution:**
```toml
# Reduce MTU in config
[node.overlay]
mtu = 1280  # Safe for most networks
```

## Recovery Procedures

### Recover from Corrupted Chain

```bash
# Backup current chain
cp /var/lib/botlink/chain.dat /var/lib/botlink/chain.dat.bak

# Remove corrupted chain
rm /var/lib/botlink/chain.dat

# Restart - will sync from peers
systemctl restart botlink
```

### Reset Node Identity

```bash
# Stop service
systemctl stop botlink

# Generate new keys
./botlink-keygen ed25519 > /etc/botlink/ed25519.keys
./botlink-keygen x25519 > /etc/botlink/x25519.keys

# Update config with new keys
# Edit /etc/botlink/config.toml

# Remove old chain (new identity = new membership needed)
rm /var/lib/botlink/chain.dat

# Start with new identity
systemctl start botlink
```

### Emergency Shutdown

```bash
# Graceful shutdown
systemctl stop botlink

# Force kill if hung
pkill -9 botlink-node

# Remove stale socket
rm -f /var/run/botlink.sock
```

## Getting Help

If issues persist:

1. Check GitHub Issues for known problems
2. Collect debug logs and packet captures
3. Open a new issue with:
   - Botlink version
   - Operating system
   - Configuration (redact private keys)
   - Full debug log
   - Steps to reproduce
