# ShadowGate - Next-Gen Stealth Redirector & Deception Gateway

**Language:** Go
**Category:** Red-team Infra Protection / Stealth Proxy / Deception Layer

---

## 1. Overview

**ShadowGate** is a **Go-based, modular stealth redirector, traffic filter, and deception gateway** designed for red-team operations.

It sits **in front of C2 servers, phishing infrastructure, and payload delivery systems** and:

* Filters and classifies inbound traffic
* Hides and protects real infrastructure
* Serves decoy content to scanners/defenders
* Shapes and mimics legitimate traffic patterns
* Automates parts of infra rotation and management
* Produces logs, IOCs, and engagement reports

---

## 2. Objectives

1. Provide a **high-performance, low-noise redirector** with a small operational footprint.
2. Deliver **advanced OPSEC**:
   * Dynamic fingerprinting (TLS, HTTP, behavioral)
   * Adaptive allow/deny decisions
   * Deception instead of simple blocking
3. Support **multiple backends and protocols** with a plugin-friendly architecture.
4. Offer **infra automation hooks** for rotating domains/IPs, managing certs, and deploying at scale.
5. Enable **forensic-friendly logging and IOC export** without compromising OPSEC.
6. Be **extensible** via clearly defined interfaces for rules, protocols, and decoys.

---

## 3. Non-Goals

* Not a C2 framework or RAT.
* Not an email/phishing campaign manager.
* Not a full SIEM or SOC platform.
* Not a general vulnerability scanner/exploitation framework.

---

## 4. Primary Use Cases

* **Fronting HTTP/S C2 callbacks** with stealth filters.
* **Protecting phishing sites** from automated scanners, sandboxes, and IR teams.
* **Gating DNS or raw TCP redirectors** for custom C2 channels.
* **Creating multi-layer redirect chains** for high-OPSEC engagements.
* **Running deception-heavy infra** for red-team/blue-team exercises.

---

## 5. Design Principles

* **Go first**: single static binary, cross-platform builds.
* **Config-driven behavior**: YAML/TOML/JSON with hot-reload.
* **Deny by default**: explicit allow logic, safe error modes.
* **Modular & pluggable**: filters, decoys, protocols, and outputs are components.
* **Stealth + observability**: rich analytics, but encrypted and controlled.

---

## 6. High-Level Architecture

### 6.1 Core Components

1. **Listener Layer** - Listens on configured IP/port pairs (HTTP/HTTPS, TCP, DNS, UDP)
2. **Profile** - Logical unit binding listeners, backends, rules, and decoy config
3. **Rule & Filter Engine** - Pipeline of rules with boolean logic and plugin interface
4. **Decision Engine** - Returns actions: ALLOW_FORWARD, DENY_DECOY, DROP, TARPIT, REDIRECT
5. **Backend Proxy Layer** - Reverse proxy to configured backends with health checks
6. **Deception Engine** - Static decoys, decoy backends, honeypot paths
7. **Traffic Shaping & Mimicry Module** - Delay injection, response padding, header variations
8. **Telemetry, Logging & Forensics** - Event logs, request metadata, IOC export
9. **Configuration & Control Plane** - YAML config, hot-reload, optional Admin API
10. **Automation & Infra Integration** - IaC artifacts, rotation hooks, ACME integration

---

## 7. Phased Roadmap

### Phase 1 - MVP
- HTTP(S) + TCP proxy
- Static IP/UA/time rules
- Simple decoy and redirect behavior
- JSON logging to file
- Docker support
- Basic documentation

### Phase 2 - Advanced Filtering & Deception
- ASN/GeoIP rules
- TLS fingerprint and SNI rules
- Behavioral rules (scanner heuristics)
- Honeypot paths and richer decoys
- Metrics counters and simple exporters

### Phase 3 - Automation & Infra
- Domain/IP rotation hooks
- Health checks and backend failover
- Terraform/Ansible examples
- Basic Admin API for status/reload

### Phase 4 - Forensics & Reporting
- IOC export
- Engagement summary generator
- Optional payload logging (opt-in)

### Phase 5 - Team & Multi-Operator (Optional)
- Admin API with RBAC
- Audit log of config changes
- Multi-profile/team separation

---

## 8. Configuration Example

```yaml
global:
  log:
    level: info
    format: json
    sink: file
    path: /var/log/shadowgate.log
    encrypt: true
  geoip_db_path: /opt/shadowgate/geoip.mmdb

profiles:
  - id: c2-http
    listeners:
      - addr: "0.0.0.0:443"
        protocol: http
    backends:
      - name: c2-primary
        url: https://127.0.0.1:8443
        weight: 10
    rules:
      allow:
        and:
          - type: ip_allow_list
            list: [ "10.0.0.0/8", "203.0.113.0/24" ]
          - type: ua_whitelist
            patterns: [ ".*Chrome.*", ".*Firefox.*" ]
      deny:
        or:
          - type: asn_block
            list: [ "AS12345", "AS67890" ]
          - type: scanner_behavior
    decoy:
      mode: static
      status_code: 200
      body_file: /opt/shadowgate/decoys/landing.html
    shaping:
      delay_ms_min: 50
      delay_ms_max: 200
```

---

## 9. Deliverables

* Complete Go codebase aligned to this scope
* Build tooling (Makefile/GoReleaser)
* Prebuilt binaries + Docker images for main platforms
* Documentation (Architecture, Config reference, Deployment scenarios)
* Sample configs for common scenarios
* OPSEC guidance and usage disclaimer
