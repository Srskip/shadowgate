# ShadowGate Ansible Role

Deploy and configure ShadowGate on Linux servers.

## Requirements

- Ansible 2.10+
- Target: RHEL/CentOS 8+, Ubuntu 20.04+, Debian 11+

## Quick Start

1. Copy the inventory example:
   ```bash
   cp inventory.example inventory
   ```

2. Edit the inventory with your server details.

3. Place the ShadowGate binary in `roles/shadowgate/files/shadowgate`

4. Place TLS certificates in `files/` directory (if using TLS)

5. Run the playbook:
   ```bash
   ansible-playbook -i inventory playbook.yml
   ```

## Role Variables

See `roles/shadowgate/defaults/main.yml` for all available variables.

### Key Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `shadowgate_user` | `shadowgate` | System user |
| `shadowgate_install_dir` | `/opt/shadowgate` | Binary location |
| `shadowgate_config_dir` | `/etc/shadowgate` | Config location |
| `shadowgate_http_port` | `8080` | HTTP port |
| `shadowgate_https_port` | `8443` | HTTPS port |
| `shadowgate_tls_enabled` | `false` | Enable TLS |
| `shadowgate_profiles` | `[]` | Profile configurations |

## Example Profile

```yaml
shadowgate_profiles:
  - id: "c2-front"
    listener:
      addr: ":443"
      tls:
        cert_file: "/etc/shadowgate/server.crt"
        key_file: "/etc/shadowgate/server.key"
    backends:
      - name: "c2-server"
        url: "http://10.0.1.10:8080"
        weight: 10
    rules:
      - type: "geo_allow"
        countries: ["US", "CA"]
      - type: "rate_limit"
        requests_per_second: 10
        burst: 20
    decoy:
      type: "static"
      status_code: 404
      content: "<html><body>Not Found</body></html>"
```

## Directory Structure

```
deploy/ansible/
├── playbook.yml           # Main playbook
├── inventory.example      # Example inventory
├── README.md
└── roles/
    └── shadowgate/
        ├── defaults/main.yml    # Default variables
        ├── tasks/main.yml       # Installation tasks
        ├── handlers/main.yml    # Service handlers
        ├── templates/
        │   ├── config.yaml.j2   # Config template
        │   └── shadowgate.service.j2
        ├── files/               # Place binary here
        └── meta/main.yml        # Role metadata
```

## Service Management

```bash
# Check status
systemctl status shadowgate

# View logs
journalctl -u shadowgate -f

# Reload configuration
curl -X POST http://127.0.0.1:9090/reload
```
