#!/bin/bash
# ShadowGate Manual Installation Script
# Run as root or with sudo

set -e

INSTALL_DIR="/opt/shadowgate"
CONFIG_DIR="/etc/shadowgate"
LOG_DIR="/var/log/shadowgate"
DATA_DIR="/var/lib/shadowgate"
USER="shadowgate"
GROUP="shadowgate"

echo "Installing ShadowGate..."

# Create system user and group
if ! getent group "$GROUP" > /dev/null; then
    groupadd --system "$GROUP"
    echo "Created group: $GROUP"
fi

if ! getent passwd "$USER" > /dev/null; then
    useradd --system --gid "$GROUP" --shell /sbin/nologin --home "$DATA_DIR" "$USER"
    echo "Created user: $USER"
fi

# Create directories
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
chown "$USER:$GROUP" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
chmod 755 "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"

# Copy binary (must be in current directory)
if [ -f "./shadowgate" ]; then
    cp ./shadowgate "$INSTALL_DIR/shadowgate"
    chmod 755 "$INSTALL_DIR/shadowgate"
    echo "Installed binary to $INSTALL_DIR/shadowgate"
else
    echo "Warning: shadowgate binary not found in current directory"
    echo "Please copy the binary to $INSTALL_DIR/shadowgate"
fi

# Copy example config if no config exists
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    if [ -f "./config.yaml" ]; then
        cp ./config.yaml "$CONFIG_DIR/config.yaml"
    else
        cat > "$CONFIG_DIR/config.yaml" << 'EOF'
# ShadowGate Configuration
# See documentation for full options

global:
  log:
    level: info
    format: json
    file: /var/log/shadowgate/shadowgate.log
  admin_addr: "127.0.0.1:9090"

profiles:
  - id: "default"
    listener:
      addr: ":8080"
    backends:
      - name: "backend1"
        url: "http://127.0.0.1:8000"
        weight: 10
    health_check:
      enabled: true
      interval: 10s
      timeout: 5s
    rules:
      - type: "ip_allow"
        cidrs:
          - "0.0.0.0/0"
    decoy:
      type: "static"
      content: "<html><body>Not Found</body></html>"
      content_type: "text/html"
      status_code: 404
EOF
    fi
    chown "$USER:$GROUP" "$CONFIG_DIR/config.yaml"
    chmod 640 "$CONFIG_DIR/config.yaml"
    echo "Created default config at $CONFIG_DIR/config.yaml"
fi

# Install systemd service
cp ./shadowgate.service /etc/systemd/system/shadowgate.service
chmod 644 /etc/systemd/system/shadowgate.service
systemctl daemon-reload
echo "Installed systemd service"

# Enable service
systemctl enable shadowgate
echo "Enabled shadowgate service"

echo ""
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Edit configuration: $CONFIG_DIR/config.yaml"
echo "  2. Start service: systemctl start shadowgate"
echo "  3. Check status: systemctl status shadowgate"
echo "  4. View logs: journalctl -u shadowgate -f"
echo ""
