"""
SSL/TLS Certificate & Cipher Auditor (Passive)
Inspects public TLS configuration, certificate validity, SANs, and protocol versions.
"""
import socket
import ssl
import datetime
from typing import Dict, Any, List

class SSLChecker:
    def __init__(self, host: str, port: int = 443, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout

    def analyze(self) -> Dict[str, Any]:
        result = {
            "host": self.host,
            "port": self.port,
            "connected": False,
            "tls_version": None,
            "cipher": None,
            "cert": {},
            "findings": [],
            "score": 100,
            "error": None
        }

        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        # Intento de conexión con verificación estándar
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    result["connected"] = True
                    result["tls_version"] = ssock.version()
                    cipher_info = ssock.cipher()
                    result["cipher"] = {
                        "name": cipher_info[0] if cipher_info else None,
                        "protocol": cipher_info[1] if cipher_info else None,
                        "bits": cipher_info[2] if cipher_info else None
                    }
                    cert = ssock.getpeercert()
                    result["cert"] = self._parse_cert(cert)
        except ssl.SSLCertVerificationError as e:
            result["connected"] = True
            result["error"] = f"Fallo de verificación de certificado: {e.verify_message}"
            result["findings"].append({
                "type": "CERTIFICATE_VERIFICATION_FAILED",
                "severity": "HIGH",
                "description": f"El certificado no es de confianza o no coincide con el host: {e.verify_message}",
                "recommendation": "Instalar un certificado válido emitido por una Autoridad Certificadora (CA) pública confiable."
            })
            # Obtener datos sin verificar para diagnóstico
            unverified_cert = self._get_unverified_cert()
            if unverified_cert:
                result["cert"] = unverified_cert
        except Exception as e:
            result["error"] = str(e)
            result["findings"].append({
                "type": "SSL_CONNECTION_FAILED",
                "severity": "HIGH",
                "description": f"No se pudo establecer conexión SSL/TLS en {self.host}:{self.port} ({e})",
                "recommendation": "Verificar que el puerto 443 esté abierto y con un servicio TLS activo."
            })
            result["score"] = 0
            return result

        # Evaluar hallazgos del certificado
        self._evaluate_findings(result)
        return result

    def _parse_cert(self, cert: dict) -> Dict[str, Any]:
        parsed = {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "version": cert.get("version"),
            "serial_number": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"],
            "days_remaining": None,
            "is_expired": False
        }

        # Calcular días restantes
        if parsed["not_after"]:
            try:
                # Formato estándar 'Feb 15 12:00:00 2026 GMT'
                exp_date = datetime.datetime.strptime(parsed["not_after"], "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                delta = exp_date - now
                parsed["days_remaining"] = delta.days
                parsed["is_expired"] = delta.days < 0
            except Exception:
                pass

        return parsed

    def _get_unverified_cert(self) -> Dict[str, Any]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    return self._parse_cert(cert)
        except Exception:
            return {}

    def _evaluate_findings(self, result: Dict[str, Any]):
        cert = result.get("cert", {})
        tls_version = result.get("tls_version")
        score = 100

        # Evaluar versión de TLS
        if tls_version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
            score -= 40
            result["findings"].append({
                "type": "DEPRECATED_TLS_VERSION",
                "severity": "HIGH",
                "description": f"El servidor utiliza una versión obsoleta e insegura de TLS: {tls_version}",
                "recommendation": "Deshabilitar TLS 1.0 y TLS 1.1 en el servidor web. Exigir mínimo TLS 1.2 y preferir TLS 1.3."
            })
        elif tls_version == "TLSv1.2":
            result["findings"].append({
                "type": "TLS_VERSION_OK",
                "severity": "INFO",
                "description": "Conexión negociada en TLS 1.2. Protocolo seguro y vigente.",
                "recommendation": "Considerar habilitar TLS 1.3 para optimizar rendimiento y seguridad de cifrado."
            })
        elif tls_version == "TLSv1.3":
            result["findings"].append({
                "type": "MODERN_TLS_VERSION",
                "severity": "GOOD",
                "description": "Conexión establecida con TLS 1.3 (estándar moderno más seguro y eficiente).",
                "recommendation": "Mantener esta configuración."
            })

        # Evaluar expiración del certificado
        days = cert.get("days_remaining")
        if days is not None:
            if days < 0:
                score -= 50
                result["findings"].append({
                    "type": "EXPIRED_CERTIFICATE",
                    "severity": "CRITICAL",
                    "description": f"El certificado SSL expiró hace {abs(days)} días.",
                    "recommendation": "Renovar el certificado SSL/TLS de forma urgente para evitar bloqueos del navegador."
                })
            elif days < 15:
                score -= 25
                result["findings"].append({
                    "type": "EXPIRING_CERTIFICATE_SOON",
                    "severity": "HIGH",
                    "description": f"El certificado SSL expirará en menos de 15 días ({days} días restantes).",
                    "recommendation": "Renovar el certificado inmediatamente."
                })
            elif days < 30:
                score -= 10
                result["findings"].append({
                    "type": "EXPIRING_CERTIFICATE_WARNING",
                    "severity": "MEDIUM",
                    "description": f"El certificado SSL expirará pronto ({days} días restantes).",
                    "recommendation": "Planificar la renovación del certificado en los próximos días."
                })
            else:
                result["findings"].append({
                    "type": "CERTIFICATE_VALIDITY_OK",
                    "severity": "GOOD",
                    "description": f"Certificado vigente con {days} días de validez restante.",
                    "recommendation": "Mantener monitoreo automatizado de renovación."
                })

        # Evaluar longitud de bits del cifrado
        cipher = result.get("cipher") or {}
        bits = cipher.get("bits")
        if bits and bits < 128:
            score -= 30
            result["findings"].append({
                "type": "WEAK_CIPHER_SUITE",
                "severity": "HIGH",
                "description": f"Longitud de clave de cifrado débil ({bits} bits).",
                "recommendation": "Reconfigurar los cipher suites para admitir únicamente cifrados de 128 bits o 256 bits."
            })

        result["score"] = max(0, score)
