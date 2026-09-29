"""
HTTP Security Headers & Cookies Analyzer (Passive)
Evaluates HTTP response headers against OWASP and industry best practices.
"""
import urllib.request
import urllib.error
import ssl
from typing import Dict, Any, List

class HeadersAnalyzer:
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "name": "HTTP Strict Transport Security (HSTS)",
            "required": True,
            "weight": 25,
            "description": "Fuerza conexiones HTTPS y mitiga ataques de downgrade SSL/TLS (SSL stripping)."
        },
        "Content-Security-Policy": {
            "name": "Content Security Policy (CSP)",
            "required": True,
            "weight": 25,
            "description": "Restringe orígenes de scripts, hojas de estilo e imágenes para mitigar XSS y data injection."
        },
        "X-Frame-Options": {
            "name": "X-Frame-Options",
            "required": True,
            "weight": 15,
            "description": "Previene ataques de Clickjacking impidiendo el renderizado en <iframe> no autorizados."
        },
        "X-Content-Type-Options": {
            "name": "X-Content-Type-Options",
            "required": True,
            "weight": 10,
            "description": "Previene la adivinación o sniffing del tipo MIME (nosniff)."
        },
        "Referrer-Policy": {
            "name": "Referrer-Policy",
            "required": True,
            "weight": 10,
            "description": "Controla la cantidad de información enviada en el encabezado Referer."
        },
        "Permissions-Policy": {
            "name": "Permissions-Policy",
            "required": False,
            "weight": 10,
            "description": "Controla qué APIs del navegador (cámara, micrófono, geolocalización) pueden ejecutarse."
        }
    }

    LEAK_HEADERS = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Generator",
        "X-Runtime",
        "X-Backend-Server"
    ]

    def __init__(self, target_url: str, timeout: int = 10, user_agent: str = None):
        self.target_url = target_url
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    def analyze(self) -> Dict[str, Any]:
        result = {
            "url": self.target_url,
            "status_code": None,
            "headers": {},
            "findings": [],
            "score": 100,
            "grade": "A",
            "missing_headers": [],
            "present_headers": [],
            "leaks": [],
            "cookies": [],
            "error": None
        }

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            self.target_url,
            headers={"User-Agent": self.user_agent}
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as response:
                result["status_code"] = response.getcode()
                raw_headers = dict(response.info())
                # Normalizar keys en minúsculas y mantener diccionario original
                headers_lower = {k.lower(): v for k, v in raw_headers.items()}
                result["headers"] = raw_headers
                
                # Obtener cookies de Set-Cookie
                cookie_headers = response.info().get_all("Set-Cookie") or []
                result["cookies"] = self._analyze_cookies(cookie_headers)

        except urllib.error.HTTPError as e:
            result["status_code"] = e.code
            raw_headers = dict(e.headers)
            headers_lower = {k.lower(): v for k, v in raw_headers.items()}
            result["headers"] = raw_headers
            cookie_headers = e.headers.get_all("Set-Cookie") or []
            result["cookies"] = self._analyze_cookies(cookie_headers)
        except Exception as e:
            result["error"] = str(e)
            result["score"] = 0
            result["grade"] = "F"
            return result

        score_penalty = 0

        # 1. Evaluar encabezados de seguridad
        for header, meta in self.SECURITY_HEADERS.items():
            val = headers_lower.get(header.lower())
            if not val:
                result["missing_headers"].append(header)
                if meta["required"]:
                    score_penalty += meta["weight"]
                    result["findings"].append({
                        "type": "MISSING_SECURITY_HEADER",
                        "severity": "MEDIUM" if meta["weight"] >= 15 else "LOW",
                        "header": header,
                        "description": f"Encabezado ausente: {meta['name']}. {meta['description']}",
                        "recommendation": f"Implementar el encabezado '{header}' en el servidor web o CDN."
                    })
            else:
                result["present_headers"].append({"header": header, "value": val})
                # Análisis específico del valor
                findings_val = self._audit_header_value(header, val)
                for f in findings_val:
                    result["findings"].append(f)
                    if f["severity"] == "HIGH":
                        score_penalty += 15
                    elif f["severity"] == "MEDIUM":
                        score_penalty += 8

        # 2. Evaluar fuga de información de servidores / tecnologías
        for leak in self.LEAK_HEADERS:
            val = headers_lower.get(leak.lower())
            if val:
                result["leaks"].append({"header": leak, "value": val})
                score_penalty += 5
                result["findings"].append({
                    "type": "INFORMATION_DISCLOSURE",
                    "severity": "LOW",
                    "header": leak,
                    "value": val,
                    "description": f"Fuga de información en cabecera '{leak}': Revela '{val}' a clientes externos.",
                    "recommendation": f"Ocultar o anonimizar la cabecera '{leak}' para evitar fingerprinting."
                })

        # 3. Evaluar hallazgos en cookies
        for c in result["cookies"]:
            for issue in c.get("issues", []):
                score_penalty += 5
                result["findings"].append({
                    "type": "INSECURE_COOKIE",
                    "severity": "MEDIUM",
                    "cookie": c["name"],
                    "description": issue,
                    "recommendation": "Configurar las flags Secure, HttpOnly y SameSite=Lax/Strict en todas las cookies sensibles."
                })

        # Calcular Score final y Grado
        final_score = max(0, 100 - score_penalty)
        result["score"] = final_score
        if final_score >= 90:
            result["grade"] = "A+" if not result["missing_headers"] else "A"
        elif final_score >= 75:
            result["grade"] = "B"
        elif final_score >= 60:
            result["grade"] = "C"
        elif final_score >= 40:
            result["grade"] = "D"
        else:
            result["grade"] = "F"

        return result

    def _audit_header_value(self, header: str, value: str) -> List[Dict[str, Any]]:
        findings = []
        val_lower = value.lower()

        if header == "Strict-Transport-Security":
            if "max-age" not in val_lower:
                findings.append({
                    "type": "WEAK_HSTS_DIRECTIVE",
                    "severity": "MEDIUM",
                    "header": header,
                    "description": "Directiva max-age no encontrada en HSTS.",
                    "recommendation": "Especificar max-age=31536000 (1 año) en la cabecera Strict-Transport-Security."
                })
            else:
                try:
                    import re
                    match = re.search(r"max-age=(\d+)", val_lower)
                    if match:
                        age = int(match.group(1))
                        if age < 15552000: # < 180 días
                            findings.append({
                                "type": "SHORT_HSTS_LIFETIME",
                                "severity": "LOW",
                                "header": header,
                                "description": f"Tiempo max-age de HSTS ({age}s) es inferior a los 180 días recomendados.",
                                "recommendation": "Incrementar max-age a al menos 31536000 segundos."
                            })
                except Exception:
                    pass

        elif header == "Content-Security-Policy":
            if "'unsafe-inline'" in val_lower:
                findings.append({
                    "type": "WEAK_CSP_DIRECTIVE",
                    "severity": "MEDIUM",
                    "header": header,
                    "description": "CSP contiene 'unsafe-inline', lo cual debilita la protección contra ataques XSS.",
                    "recommendation": "Eliminar 'unsafe-inline' utilizando hashes o nonces para scripts en línea."
                })
            if "'unsafe-eval'" in val_lower:
                findings.append({
                    "type": "WEAK_CSP_DIRECTIVE",
                    "severity": "MEDIUM",
                    "header": header,
                    "description": "CSP contiene 'unsafe-eval', permitiendo ejecución dinámica de código JS.",
                    "recommendation": "Refactorizar código para evitar eval() y eliminar 'unsafe-eval'."
                })

        return findings

    def _analyze_cookies(self, cookie_headers: List[str]) -> List[Dict[str, Any]]:
        cookies = []
        for raw in cookie_headers:
            parts = [p.strip() for p in raw.split(";")]
            if not parts:
                continue
            name_val = parts[0]
            cookie_name = name_val.split("=")[0] if "=" in name_val else name_val
            flags = [p.lower() for p in parts[1:]]
            
            is_secure = "secure" in flags
            is_httponly = "httponly" in flags
            samesite = None
            for f in flags:
                if f.startswith("samesite="):
                    samesite = f.split("=")[1]
            
            issues = []
            if not is_secure:
                issues.append(f"Cookie '{cookie_name}' carece del atributo 'Secure' (se transmite en texto claro por HTTP).")
            if not is_httponly:
                issues.append(f"Cookie '{cookie_name}' carece del atributo 'HttpOnly' (accesible mediante JavaScript / riesgo XSS).")
            if not samesite:
                issues.append(f"Cookie '{cookie_name}' no define 'SameSite' (vulnerable a CSRF en navegadores antiguos).")

            cookies.append({
                "name": cookie_name,
                "raw": raw,
                "secure": is_secure,
                "httponly": is_httponly,
                "samesite": samesite,
                "issues": issues
            })
        return cookies
