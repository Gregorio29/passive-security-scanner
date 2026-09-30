# Passive Security Scanner & Recon Toolkit

[English](README.md) | [Español](README.es.md)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: Passive](https://img.shields.io/badge/Scan%20Type-Non--Intrusive-green.svg)](#)

A modular, fast, and non-intrusive passive security auditing engine written in pure Python. Evaluates external domain posture, HTTP security headers, SSL/TLS certificates, DNS anti-spoofing policies (SPF, DMARC, MX), and attack surface exposure without sending intrusive payloads or triggering alerts.

---

## 🚀 Features

- **HTTP Security Headers:** Evaluates HSTS, Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and cookie security attributes (`Secure`, `HttpOnly`, `SameSite`).
- **SSL/TLS Certificate Inspection:** Verifies negotiated protocol version (TLS 1.3 / 1.2 vs deprecated TLS 1.0 / 1.1), validity window, expiration countdown, CA issuer, and Subject Alternative Names (SANs).
- **DNS & Anti-Spoofing Mail Security:** Performs DNS-over-HTTPS (DoH via Cloudflare / Google) lookups to validate SPF (`v=spf1`), DMARC (`_dmarc`), and MX records for email security compliance.
- **Surface Posture & RFC 9116:** Audits HTTP-to-HTTPS forced redirection, `robots.txt` disallow paths, `security.txt` vulnerability disclosure metadata, and technology signatures.
- **Automated Reporting:** Generates executive Markdown (`.md`) reports with risk matrices and structured JSON (`.json`) artifacts.
- **Zero Heavy Dependencies:** Relies on standard library networking and lightweight HTTP utilities.

---

## 🛠️ Architecture

```text
passive_scanner/
├── modules/
│   ├── headers_analyzer.py  # HTTP response headers and cookie security flags
│   ├── ssl_checker.py       # x509 certificate lifecycle & TLS cipher audit
│   ├── dns_recon.py         # DoH lookups, SPF, DMARC, and MX record validation
│   ├── surface_recon.py     # HTTPS enforcement, robots.txt & RFC 9116 security.txt
│   └── reporter.py          # Structured Markdown and JSON report generator
├── reports/                 # Output folder for generated scan artifacts
├── docs/                    # Technical documentation & architecture
├── examples/                # Code examples & sample reports
├── tests/                   # Unit test suite
├── scanner.py               # Main CLI entrypoint
├── requirements.txt         # Minimal dependency definitions
└── LICENSE                  # MIT License
```

---

## 📦 Installation

```bash
git clone https://github.com/<username>/passive-security-scanner.git
cd passive-security-scanner
pip install -r requirements.txt
```

---

## 💻 CLI Usage

### Basic Scan
```bash
python scanner.py -t example.com
```

### Specify Output Directory and Custom Timeout
```bash
python scanner.py -t example.com -o ./reports --timeout 15
```

### Quiet Mode (JSON Output Focus)
```bash
python scanner.py -t example.com -q
```

---

## 🐍 Programmatic Usage

```python
from scanner import run_scan

result = run_scan(target="example.com", quiet=True)
print(f"Target: {result['target']}")
print(f"Score:  {result['overall_score']}/100 (Grade: {result['overall_grade']})")
```

---

## 🧪 Running Tests

```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
