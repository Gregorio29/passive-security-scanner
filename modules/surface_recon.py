"""
Surface & Information Disclosure Reconnaissance (Passive)
Audits HTTP to HTTPS enforcement, robots.txt, security.txt, and passive CMS/tech footprint.
"""
import urllib.request
import urllib.error
import ssl
import re
from typing import Dict, Any, List

class SurfaceRecon:
    SENSITIVE_PATTERNS = [
        r"/admin",
        r"/wp-admin",
        r"/wp-content",
        r"/administrator",
        r"/login",
        r"/portal",
        r"/backup",
        r"/config",
        r"/database",
        r"/api",
        r"/secret",
        r"/private",
        r"/intranet",
        r"/cpanel",
        r"/phpmyadmin",
        r"/server-status"
    ]

    def __init__(self, target_host: str, timeout: int = 8, user_agent: str = None):
        self.target_host = target_host.replace("http://", "").replace("https://", "").split("/")[0]
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    def analyze(self) -> Dict[str, Any]:
        result = {
            "host": self.target_host,
            "http_redirect": {},
            "robots_txt": {},
            "security_txt": {},
            "sitemap_xml": {},
            "technologies": [],
            "findings": [],
            "score": 100
        }

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # 1. Auditar redirección HTTP -> HTTPS
        self._audit_http_redirect(result)

        # 2. Auditar robots.txt
        self._audit_robots(result, ctx)

        # 3. Auditar security.txt (RFC 9116)
        self._audit_security_txt(result, ctx)

        # 4. Auditar sitemap.xml
        self._audit_sitemap(result, ctx)

        # 5. Detección pasiva básica de CMS / tecnologías en la raíz
        self._audit_root_fingerprint(result, ctx)

        return result

    def _audit_http_redirect(self, result: Dict[str, Any]):
        http_url = f"http://{self.target_host}/"
        try:
            # Desactivar redirección automática para verificar si el primer salto es 301/302 a https
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def http_error_302(self, req, fp, code, msg, headers):
                    return fp
                http_error_301 = http_error_302
                http_error_303 = http_error_302
                http_error_307 = http_error_302
                http_error_308 = http_error_302

            opener = urllib.request.build_opener(NoRedirectHandler)
            req = urllib.request.Request(http_url, headers={"User-Agent": self.user_agent})
            
            with opener.open(req, timeout=self.timeout) as resp:
                code = resp.getcode()
                location = resp.headers.get("Location", "")
                result["http_redirect"] = {
                    "status_code": code,
                    "location": location,
                    "enforces_https": location.startswith("https://") if location else False
                }

                if code in [301, 308] and location.startswith("https://"):
                    result["findings"].append({
                        "type": "SECURE_HTTP_REDIRECT",
                        "severity": "GOOD",
                        "description": f"El tráfico HTTP en texto claro redirige permanentemente ({code}) a HTTPS ({location}).",
                        "recommendation": "Mantener esta configuración de redirección forzada."
                    })
                elif code in [302, 307] and location.startswith("https://"):
                    result["findings"].append({
                        "type": "TEMPORARY_HTTP_REDIRECT",
                        "severity": "LOW",
                        "description": f"El tráfico HTTP redirige temporalmente ({code}) a HTTPS. Se recomienda redirección permanente (301/308).",
                        "recommendation": "Configurar una redirección 301 Moved Permanently o 308 Permanent Redirect."
                    })
                elif not location.startswith("https://"):
                    result["score"] -= 15
                    result["findings"].append({
                        "type": "HTTP_NOT_REDIRECTED_TO_HTTPS",
                        "severity": "HIGH",
                        "description": f"El puerto 80 (HTTP) no redirige a HTTPS automáticamente (Código: {code}).",
                        "recommendation": "Configurar una redirección forzada de HTTP a HTTPS a nivel de servidor web o CDN."
                    })
        except Exception as e:
            result["http_redirect"] = {"error": str(e), "enforces_https": False}

    def _audit_robots(self, result: Dict[str, Any], ctx: ssl.SSLContext):
        url = f"https://{self.target_host}/robots.txt"
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                if resp.getcode() == 200:
                    content = resp.read().decode("utf-8", errors="ignore")
                    disallow_lines = []
                    sensitive_found = []
                    
                    for line in content.splitlines():
                        line_clean = line.strip()
                        if line_clean.lower().startswith("disallow:"):
                            path = line_clean.split(":", 1)[1].strip()
                            disallow_lines.append(path)
                            for pat in self.SENSITIVE_PATTERNS:
                                if re.search(pat, path, re.IGNORECASE):
                                    sensitive_found.append(path)

                    result["robots_txt"] = {
                        "present": True,
                        "disallow_count": len(disallow_lines),
                        "sensitive_paths": list(set(sensitive_found)),
                        "snippet": content[:500]
                    }

                    if sensitive_found:
                        result["findings"].append({
                            "type": "ROBOTS_TXT_DISCLOSED_SENSITIVE_PATHS",
                            "severity": "LOW",
                            "description": f"robots.txt divulga rutas potencialmente sensibles de administración o backend ({len(sensitive_found)} detectadas).",
                            "recommendation": "Evitar incluir rutas críticas en robots.txt si su confidencialidad es relevante; restringir acceso con autenticación y WAF."
                        })
                    else:
                        result["findings"].append({
                            "type": "ROBOTS_TXT_FOUND",
                            "severity": "INFO",
                            "description": f"robots.txt accesible ({len(disallow_lines)} reglas Disallow).",
                            "recommendation": "Revisar periódicamente para no exponer endpoints internos."
                        })
                else:
                    result["robots_txt"] = {"present": False, "status_code": resp.getcode()}
        except Exception:
            result["robots_txt"] = {"present": False}

    def _audit_security_txt(self, result: Dict[str, Any], ctx: ssl.SSLContext):
        urls = [
            f"https://{self.target_host}/.well-known/security.txt",
            f"https://{self.target_host}/security.txt"
        ]
        found = False
        for url in urls:
            req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    if resp.getcode() == 200:
                        content = resp.read().decode("utf-8", errors="ignore")
                        if "Contact:" in content:
                            result["security_txt"] = {
                                "present": True,
                                "url": url,
                                "content": content[:500]
                            }
                            result["findings"].append({
                                "type": "SECURITY_TXT_PRESENT",
                                "severity": "GOOD",
                                "description": f"Archivo RFC 9116 security.txt presente en {url}.",
                                "recommendation": "Mantener actualizados los canales de contacto de divulgación coordinada de vulnerabilidades."
                            })
                            found = True
                            break
            except Exception:
                continue

        if not found:
            result["security_txt"] = {"present": False}
            result["findings"].append({
                "type": "SECURITY_TXT_MISSING",
                "severity": "INFO",
                "description": "No se encontró archivo RFC 9116 security.txt en /.well-known/security.txt.",
                "recommendation": "Implementar un archivo security.txt para facilitar el reporte responsable de vulnerabilidades por investigadores."
            })

    def _audit_sitemap(self, result: Dict[str, Any], ctx: ssl.SSLContext):
        url = f"https://{self.target_host}/sitemap.xml"
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                if resp.getcode() == 200:
                    result["sitemap_xml"] = {"present": True, "url": url}
                else:
                    result["sitemap_xml"] = {"present": False}
        except Exception:
            result["sitemap_xml"] = {"present": False}

    def _audit_root_fingerprint(self, result: Dict[str, Any], ctx: ssl.SSLContext):
        url = f"https://{self.target_host}/"
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
                
                # Buscar meta generator
                match_gen = re.search(r'<meta[^>]+name=[\'"]generator[\'"][^>]+content=[\'"]([^\'"]+)[\'"]', html, re.IGNORECASE)
                if match_gen:
                    gen_val = match_gen.group(1)
                    result["technologies"].append({"type": "CMS/Generator", "value": gen_val})
                    result["findings"].append({
                        "type": "META_GENERATOR_EXPOSED",
                        "severity": "LOW",
                        "description": f"Etiqueta <meta name='generator'> expone la tecnología: {gen_val}",
                        "recommendation": "Eliminar la etiqueta generator del template para dificultar el fingerprinting automatizado."
                    })

                # Buscar huellas de WordPress
                if "wp-content" in html or "wp-includes" in html:
                    result["technologies"].append({"type": "Platform", "value": "WordPress"})

                # Buscar huellas de Cloudflare
                cf_ray = resp.headers.get("cf-ray")
                if cf_ray:
                    result["technologies"].append({"type": "WAF/CDN", "value": "Cloudflare"})
        except Exception:
            pass
