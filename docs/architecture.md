# Passive Security Scanner — Technical Architecture

## Overview
The Passive Security Scanner operates strictly on public signals and standard protocol handshakes without generating offensive payloads or exploiting vulnerabilities.

```text
                       ┌────────────────────────┐
                       │       scanner.py       │
                       │   (CLI Orchestrator)   │
                       └───────────┬────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         │                         │                         │
         ▼                         ▼                         ▼
┌───────────────────┐    ┌───────────────────┐    ┌───────────────────┐
│ headers_analyzer  │    │    ssl_checker    │    │     dns_recon     │
│  - Security Hdr   │    │  - Certificate    │    │  - DoH Lookups    │
│  - Cookie Flags   │    │  - Validity / SAN │    │  - SPF / DMARC    │
└────────┬──────────┘    └─────────┬─────────┘    └──────────┬────────┘
         │                         │                         │
         └─────────────────────────┼─────────────────────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │   surface_recon   │
                         │ - HTTPS Redirect  │
                         │ - robots.txt      │
                         │ - RFC 9116 Sec.txt│
                         └─────────┬─────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │    reporter.py    │
                         │ - JSON Artifact   │
                         │ - Markdown Report │
                         └───────────────────┘
```

## Scoring Formula
Each module evaluates compliance against RFC and OWASP security recommendations and produces a score from 0 to 100:

- **Headers:** Evaluates presence and strictness of HSTS (25%), CSP (25%), X-Frame-Options (15%), X-Content-Type-Options (10%), Referrer-Policy (10%), Permissions-Policy (5%), and Cookie flags (10%).
- **SSL/TLS:** Evaluates protocol versions (TLS 1.3/1.2 = pass; TLS 1.0/1.1 = fail), certificate expiration window, valid CN/SANs, and trusted issuer.
- **DNS & Mail Security:** Evaluates SPF syntax correctness, DMARC `p=reject` / `p=quarantine` policies, and MX accessibility.
- **Surface Posture:** Evaluates automatic HTTP to HTTPS 301/308 enforcement and security contact presence (`security.txt`).
