"""
Security Audit Reporter
Generates comprehensive Markdown and JSON reports from passive scan results.
"""
import json
import os
import datetime
from typing import Dict, Any

class Reporter:
    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "GOOD": 5}
    SEVERITY_BADGES = {
        "CRITICAL": "🔴 CRÍTICA",
        "HIGH": "🟠 ALTA",
        "MEDIUM": "🟡 MEDIA",
        "LOW": "🔵 BAJA",
        "INFO": "ℹ️ INFO",
        "GOOD": "🟢 ADECUADO"
    }

    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.target = data.get("target", "unknown")
        self.timestamp = data.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def generate_markdown(self) -> str:
        d = self.data
        score = d.get("overall_score", 0)
        grade = d.get("overall_grade", "F")
        findings = d.get("all_findings", [])

        # Ordenar hallazgos por severidad
        findings_sorted = sorted(findings, key=lambda x: self.SEVERITY_ORDER.get(x.get("severity", "INFO"), 99))

        md = []
        md.append(f"# 🛡️ Informe de Auditoría de Seguridad Pasiva")
        md.append(f"**Objetivo:** `{self.target}`  ")
        md.append(f"**Fecha y Hora:** `{self.timestamp}`  ")
        md.append(f"**Puntuación Global:** `{score}/100` | **Calificación:** `{grade}`  ")
        md.append(f"**Tipo de Análisis:** Escaneo Pasivo No Intrusivo (Headers, SSL/TLS, DNS/DMARC/SPF, Surface)  ")
        md.append("\n---\n")

        # Resumen Ejecutivo
        md.append("## 1. Resumen Ejecutivo\n")
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "GOOD": 0}
        for f in findings:
            sev = f.get("severity", "INFO")
            if sev in counts:
                counts[sev] += 1

        md.append("| Nivel de Severidad | Total Hallazgos |")
        md.append("| :--- | :---: |")
        for sev, label in self.SEVERITY_BADGES.items():
            md.append(f"| {label} | **{counts[sev]}** |")
        md.append("")

        # Tabla de Hallazgos y Vulnerabilidades
        md.append("## 2. Matriz de Hallazgos y Recomendaciones\n")
        if not findings_sorted:
            md.append("No se detectaron observaciones durante el escaneo pasivo.\n")
        else:
            md.append("| Severidad | Categoría / Tipo | Descripción | Recomendación |")
            md.append("| :--- | :--- | :--- | :--- |")
            for f in findings_sorted:
                badge = self.SEVERITY_BADGES.get(f.get("severity", "INFO"), f.get("severity"))
                ftype = f.get("type", "GENERAL")
                desc = f.get("description", "").replace("|", "\\|")
                recom = f.get("recommendation", "").replace("|", "\\|")
                md.append(f"| {badge} | `{ftype}` | {desc} | {recom} |")
            md.append("")

        # Detalle de Módulos
        md.append("## 3. Detalle Técnico por Módulo\n")

        # 3.1 Encabezados HTTP
        headers_mod = d.get("modules", {}).get("headers", {})
        md.append("### 3.1 Cabeceras de Seguridad HTTP")
        md.append(f"- **Puntuación Headers:** `{headers_mod.get('score', 0)}/100` (Grado: `{headers_mod.get('grade', 'N/A')}`)")
        missing_h = headers_mod.get("missing_headers", [])
        if missing_h:
            md.append(f"- **Cabeceras Ausentes:** {', '.join([f'`{h}`' for h in missing_h])}")
        else:
            md.append("- **Cabeceras Ausentes:** Ninguna (Todas las recomendadas están presentes).")
        
        leaks = headers_mod.get("leaks", [])
        if leaks:
            leak_str = ", ".join([f"`{l['header']}: {l['value']}`" for l in leaks])
            md.append(f"- **Fuga de Información en Servidor:** {leak_str}")

        cookies = headers_mod.get("cookies", [])
        if cookies:
            md.append(f"- **Cookies Evaluadas ({len(cookies)}):**")
            for c in cookies:
                sec_s = "✅ Secure" if c.get("secure") else "❌ Sin Secure"
                http_s = "✅ HttpOnly" if c.get("httponly") else "❌ Sin HttpOnly"
                same_s = f"SameSite={c.get('samesite')}" if c.get("samesite") else "❌ Sin SameSite"
                md.append(f"  - `{c.get('name')}`: {sec_s}, {http_s}, {same_s}")
        md.append("")

        # 3.2 SSL / TLS
        ssl_mod = d.get("modules", {}).get("ssl", {})
        md.append("### 3.2 Certificado y Cifrado SSL/TLS")
        if ssl_mod.get("connected"):
            cert = ssl_mod.get("cert", {})
            cipher = ssl_mod.get("cipher", {})
            md.append(f"- **Versión TLS Negociada:** `{ssl_mod.get('tls_version')}`")
            md.append(f"- **Cifrado Negociado:** `{cipher.get('name')} ({cipher.get('bits')} bits)`")
            md.append(f"- **Emisor del Certificado (Issuer):** `{cert.get('issuer', {}).get('organizationName', 'N/A')}` (`{cert.get('issuer', {}).get('commonName', 'N/A')}`)")
            md.append(f"- **Vigencia:** Válido hasta `{cert.get('not_after')}` ({cert.get('days_remaining')} días restantes)")
            sans = cert.get("san", [])
            if sans:
                md.append(f"- **Nombres Alternativos (SAN):** {', '.join(sans[:8])}{'...' if len(sans) > 8 else ''}")
        else:
            md.append(f"- **Estado SSL:** No se pudo conectar ({ssl_mod.get('error')})")
        md.append("")

        # 3.3 DNS y Seguridad de Correo
        dns_mod = d.get("modules", {}).get("dns", {})
        md.append("### 3.3 DNS y Protección Anti-Spoofing de Correo")
        records = dns_mod.get("records", {})
        a_recs = records.get("A", [])
        mx_recs = records.get("MX", [])
        md.append(f"- **Dirección(es) IP (A):** {', '.join(a_recs) if a_recs else 'No detectadas'}")
        md.append(f"- **Servidores MX:** {', '.join(mx_recs) if mx_recs else 'Ninguno'}")
        md.append(f"- **Registro SPF:** `{dns_mod.get('spf') or 'NO CONFIGURADO'}`")
        md.append(f"- **Registro DMARC:** `{dns_mod.get('dmarc') or 'NO CONFIGURADO'}`")
        md.append("")

        # 3.4 Superficie y Redirección
        surf_mod = d.get("modules", {}).get("surface", {})
        md.append("### 3.4 Superficie de Ataque y Divulgación")
        http_redir = surf_mod.get("http_redirect", {})
        md.append(f"- **Redirección HTTP a HTTPS:** `{'Correcta (' + str(http_redir.get('status_code')) + ')' if http_redir.get('enforces_https') else 'INSEGURA / NO FORZADA'}`")
        robots = surf_mod.get("robots_txt", {})
        md.append(f"- **robots.txt:** `{'Presente (' + str(robots.get('disallow_count', 0)) + ' rutas Disallow)' if robots.get('present') else 'No presente'}`")
        sectxt = surf_mod.get("security_txt", {})
        md.append(f"- **security.txt (RFC 9116):** `{'Presente' if sectxt.get('present') else 'No presente'}`")
        techs = surf_mod.get("technologies", [])
        if techs:
            tech_str = ", ".join([f"{t['type']}: {t['value']}" for t in techs])
            md.append(f"- **Tecnologías Detectadas:** {tech_str}")
        md.append("\n---\n")

        # Conclusiones
        md.append("## 4. Guía de Remediación Prioritaria\n")
        high_critical = [f for f in findings if f.get("severity") in ["CRITICAL", "HIGH"]]
        if high_critical:
            for idx, h in enumerate(high_critical, 1):
                md.append(f"{idx}. **{h.get('type')}**: {h.get('description')}  \n   👉 *Acción recomendada:* {h.get('recommendation')}\n")
        else:
            md.append("No se detectaron hallazgos de severidad Alta o Crítica. Se recomienda atender las observaciones de nivel Medio y Bajo para fortalecer la postura defensiva.\n")

        return "\n".join(md)

    def save_reports(self, output_dir: str) -> Dict[str, str]:
        os.makedirs(output_dir, exist_ok=True)
        slug = self.target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        md_path = os.path.join(output_dir, f"scan_{slug}_{date_str}.md")
        json_path = os.path.join(output_dir, f"scan_{slug}_{date_str}.json")

        md_content = self.generate_markdown()
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)

        return {
            "markdown_path": md_path,
            "json_path": json_path
        }
