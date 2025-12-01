# ShadowGate Systemd Deployment

Manual installation using systemd service.

## Quick Install

```bash
# Build the binary
make build

# Copy files to the deploy directory
cd deploy/systemd
cp ../../bin/shadowgate .

# Run installer as root
sudo ./install.sh
```

## Manual Installation

1. Create user and group:
   ```bash
   sudo groupadd --system shadowgate
   sudo useradd --system -g shadowgate -s /sbin/nologin shadowgate
   ```

2. Create directories:
   ```bash
   sudo mkdir -p /opt/shadowgate /etc/shadowgate /var/log/shadowgate /var/lib/shadowgate
   sudo chown shadowgate:shadowgate /etc/shadowgate /var/log/shadowgate /var/lib/shadowgate
   ```

3. Copy binary:
   ```bash
   sudo cp shadowgate /opt/shadowgate/
   sudo chmod 755 /opt/shadowgate/shadowgate
   ```

4. Copy configuration:
   ```bash
   sudo cp config.yaml /etc/shadowgate/
   sudo chown shadowgate:shadowgate /etc/shadowgate/config.yaml
   sudo chmod 640 /etc/shadowgate/config.yaml
   ```

5. Install service:
   ```bash
   sudo cp shadowgate.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable shadowgate
   sudo systemctl start shadowgate
   ```

## Service Management

```bash
# Start
sudo systemctl start shadowgate

# Stop
sudo systemctl stop shadowgate

# Restart
sudo systemctl restart shadowgate

# Reload config (via SIGHUP)
sudo systemctl reload shadowgate

# Hot reload via Admin API
curl -X POST http://127.0.0.1:9090/reload

# Status
sudo systemctl status shadowgate

# Logs
sudo journalctl -u shadowgate -f
```

## Security Features

The systemd unit includes security hardening:

- Runs as unprivileged user
- Restricted filesystem access (ProtectSystem=strict)
- No privilege escalation (NoNewPrivileges)
- Isolated temp directory (PrivateTmp)
- Capability to bind privileged ports (CAP_NET_BIND_SERVICE)

## File Locations

| Path | Description |
|------|-------------|
| `/opt/shadowgate/shadowgate` | Binary |
| `/etc/shadowgate/config.yaml` | Configuration |
| `/var/log/shadowgate/` | Log files |
| `/var/lib/shadowgate/` | Data (GeoIP DB, etc.) |
