# Passive Security Scanner & Recon Toolkit

[English](README.md) | [Español](README.es.md)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: Passive](https://img.shields.io/badge/Scan%20Type-Non--Intrusive-green.svg)](#)

Un motor modular, rápido y no invasivo de auditoría de seguridad pasiva desarrollado en Python puro. Evalúa la postura de seguridad externa de dominios, cabeceras HTTP de seguridad, certificados SSL/TLS, políticas anti-spoofing de correo (SPF, DMARC, MX) y exposición de superficie de ataque sin enviar payloads intrusivos ni activar alertas en firewalls.

---

## 🚀 Características Principales

- **Cabeceras HTTP de Seguridad:** Evalúa HSTS, Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy y atributos de seguridad en cookies (`Secure`, `HttpOnly`, `SameSite`).
- **Inspección de Certificados SSL/TLS:** Verifica la versión de protocolo negociada (TLS 1.3 / 1.2 vs TLS 1.0 / 1.1 obsoletos), ventana de vigencia, cuenta regresiva de expiración, entidad emisora (CA) y nombres alternativos del sujeto (SANs).
- **Seguridad DNS y Anti-Spoofing de Correo:** Realiza consultas DNS-over-HTTPS (DoH mediante Cloudflare / Google) para validar registros SPF (`v=spf1`), DMARC (`_dmarc`) y MX según las mejores prácticas de correo electrónico.
- **Postura de Superficie y RFC 9116:** Audita redirección forzada de HTTP a HTTPS, rutas disallow en `robots.txt`, metadatos de divulgación responsable en `security.txt` y huellas tecnológicas.
- **Reportes Automatizados:** Genera informes ejecutivos en Markdown (`.md`) con matrices de riesgo y artefactos estructurados en JSON (`.json`).
- **Cero Dependencias Pesadas:** Utiliza utilidades de red y HTTP de la biblioteca estándar de Python.

---

## 🛠️ Arquitectura del Sistema

```text
passive_scanner/
├── modules/
│   ├── headers_analyzer.py  # Análisis de cabeceras HTTP y flags de cookies
│   ├── ssl_checker.py       # Ciclo de vida de certificados x509 y cifrado TLS
│   ├── dns_recon.py         # Consultas DoH, validación de SPF, DMARC y MX
│   ├── surface_recon.py     # Forzado HTTPS, robots.txt y RFC 9116 security.txt
│   └── reporter.py          # Generador de informes estructurados en Markdown y JSON
├── reports/                 # Directorio de salida para reportes generados
├── docs/                    # Documentación técnica y arquitectura
├── examples/                # Ejemplos de uso e integración
├── tests/                   # Suite de pruebas unitarias
├── scanner.py               # Punto de entrada CLI principal
├── requirements.txt         # Definición de dependencias mínimas
└── LICENSE                  # Licencia MIT
```

---

## 📦 Instalación

```bash
git clone https://github.com/Gregorio29/passive-security-scanner.git
cd passive-security-scanner
pip install -r requirements.txt
```

---

## 💻 Uso desde la CLI

### Escaneo Básico
```bash
python scanner.py -t example.com
```

### Especificar Directorio de Salida y Timeout Personalizado
```bash
python scanner.py -t example.com -o ./reports --timeout 15
```

### Modo Silencioso (Salida Estructurada JSON)
```bash
python scanner.py -t example.com -q
```

---

## 🐍 Uso Programático (Librería Python)

```python
from scanner import run_scan

result = run_scan(target="example.com", quiet=True)
print(f"Objetivo:   {result['target']}")
print(f"Puntuación: {result['overall_score']}/100 (Calificación: {result['overall_grade']})")
```

---

## 🧪 Ejecución de Pruebas

```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 📄 Licencia

Este proyecto está distribuido bajo la [Licencia MIT](LICENSE).
