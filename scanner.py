#!/usr/bin/env python3
"""
Passive Security Scanner & Recon Toolkit
Performs non-intrusive security header, SSL/TLS, DNS, email spoofing, and surface posture scans.
"""
import sys
import os
import argparse
import datetime
from urllib.parse import urlparse

# Agregar directorio actual al path para importar módulos
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from modules.headers_analyzer import HeadersAnalyzer
from modules.ssl_checker import SSLChecker
from modules.dns_recon import DNSRecon
from modules.surface_recon import SurfaceRecon
from modules.reporter import Reporter

def normalize_target(target: str) -> tuple[str, str, str]:
    """
    Normaliza el objetivo ingresado retornando (domain, base_url, host).
    """
    target = target.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        target_url = f"https://{target}"
    else:
        target_url = target

    parsed = urlparse(target_url)
    domain = parsed.hostname or target
    host = domain
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    base_url = f"{parsed.scheme}://{domain}{f':{port}' if parsed.port else ''}"

    return domain, base_url, host

def run_scan(target: str, output_dir: str = None, timeout: int = 10, quiet: bool = False) -> dict:
    domain, base_url, host = normalize_target(target)
    if not output_dir:
        output_dir = os.path.join(CURRENT_DIR, "reports")

    if not quiet:
        print("=" * 70)
        print(f"🛡️  INICIANDO ESCANEO DE SEGURIDAD PASIVO")
        print(f"🎯 Objetivo: {domain} ({base_url})")
        print(f"⏰ Hora: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)

    # 1. Análisis de Cabeceras HTTP
    if not quiet:
        print("[1/4] 🔍 Analizando Cabeceras de Seguridad HTTP y Cookies...")
    headers_analyzer = HeadersAnalyzer(base_url, timeout=timeout)
    headers_result = headers_analyzer.analyze()

    # 2. Análisis SSL/TLS
    if not quiet:
        print("[2/4] 🔐 Evaluando Configuración de Cifrado y Certificados SSL/TLS...")
    ssl_checker = SSLChecker(host, port=443, timeout=timeout)
    ssl_result = ssl_checker.analyze()

    # 3. Reconocimiento DNS y Anti-Spoofing (SPF/DMARC/MX)
    if not quiet:
        print("[3/4] 🌐 Consultando Registros DNS, SPF, DMARC y Servidores MX...")
    dns_recon = DNSRecon(domain, timeout=timeout)
    dns_result = dns_recon.analyze()

    # 4. Superficie y Divulgación de Información
    if not quiet:
        print("[4/4] 🔎 Auditando Redirección HTTPS, robots.txt, security.txt...")
    surface_recon = SurfaceRecon(host, timeout=timeout)
    surface_result = surface_recon.analyze()

    # Consolidar todos los hallazgos
    all_findings = []
    all_findings.extend(headers_result.get("findings", []))
    all_findings.extend(ssl_result.get("findings", []))
    all_findings.extend(dns_result.get("findings", []))
    all_findings.extend(surface_result.get("findings", []))

    # Ponderación global
    # Headers: 35%, SSL: 30%, DNS: 25%, Surface: 10%
    w_headers = headers_result.get("score", 0) * 0.35
    w_ssl = ssl_result.get("score", 0) * 0.30
    w_dns = dns_result.get("score", 0) * 0.25
    w_surface = surface_result.get("score", 0) * 0.10

    overall_score = round(w_headers + w_ssl + w_dns + w_surface, 1)

    if overall_score >= 90:
        overall_grade = "A"
    elif overall_score >= 75:
        overall_grade = "B"
    elif overall_score >= 60:
        overall_grade = "C"
    elif overall_score >= 45:
        overall_grade = "D"
    else:
        overall_grade = "F"

    scan_data = {
        "target": domain,
        "base_url": base_url,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "overall_score": overall_score,
        "overall_grade": overall_grade,
        "all_findings": all_findings,
        "modules": {
            "headers": headers_result,
            "ssl": ssl_result,
            "dns": dns_result,
            "surface": surface_result
        }
    }

    # Generar y guardar reportes
    reporter = Reporter(scan_data)
    saved_files = reporter.save_reports(output_dir)
    scan_data["saved_reports"] = saved_files

    if not quiet:
        print("\n" + "=" * 70)
        print(f"📊 RESULTADO GLOBAL: {overall_score}/100 (Calificación: {overall_grade})")
        print(f"📝 Hallazgos Totales: {len(all_findings)}")
        print(f"📄 Reporte Markdown guardado en: {saved_files['markdown_path']}")
        print(f"📦 Reporte JSON guardado en:     {saved_files['json_path']}")
        print("=" * 70)

    return scan_data

def main():
    parser = argparse.ArgumentParser(
        description="Escáner pasivo y no intrusivo de seguridad para dominios web."
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Dominio o URL objetivo (ejemplo: iglesiadesantiago.cl o https://iglesiadesantiago.cl)"
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=None,
        help="Directorio donde guardar los reportes generados (por defecto: ./reports)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Tiempo límite por solicitud en segundos (por defecto: 10s)"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Modo silencioso (no imprime progreso a consola)"
    )

    args = parser.parse_args()
    try:
        run_scan(target=args.target, output_dir=args.output_dir, timeout=args.timeout, quiet=args.quiet)
    except KeyboardInterrupt:
        print("\n[!] Escaneo interrumpido por el usuario.")
        sys.exit(130)
    except Exception as e:
        print(f"\n[ERROR] Error crítico durante la ejecución: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
