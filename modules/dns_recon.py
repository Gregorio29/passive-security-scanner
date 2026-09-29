"""
DNS & Email Security Reconnaissance (Passive)
Audits DNS records, SPF, DMARC, and MX configuration for email spoofing protection.
"""
import json
import urllib.request
import urllib.parse
import subprocess
import socket
from typing import Dict, Any, List, Optional

class DNSRecon:
    DOH_PROVIDERS = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve"
    ]

    RECORD_TYPES = {
        "A": 1,
        "NS": 2,
        "CNAME": 5,
        "SOA": 6,
        "MX": 15,
        "TXT": 16,
        "AAAA": 28
    }

    def __init__(self, domain: str, timeout: int = 8):
        self.domain = domain.lower().strip()
        self.timeout = timeout

    def analyze(self) -> Dict[str, Any]:
        result = {
            "domain": self.domain,
            "records": {
                "A": [],
                "AAAA": [],
                "MX": [],
                "NS": [],
                "TXT": [],
                "DMARC": []
            },
            "spf": None,
            "dmarc": None,
            "findings": [],
            "score": 100,
            "error": None
        }

        # 1. Consultar registros A, AAAA, MX, NS, TXT
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            records = self._query_doh(self.domain, rtype)
            if not records:
                records = self._query_nslookup(self.domain, rtype)
            result["records"][rtype] = records

        # 2. Consultar DMARC (_dmarc.domain)
        dmarc_target = f"_dmarc.{self.domain}"
        dmarc_records = self._query_doh(dmarc_target, "TXT")
        if not dmarc_records:
            dmarc_records = self._query_nslookup(dmarc_target, "TXT")
        result["records"]["DMARC"] = dmarc_records

        # 3. Analizar SPF
        spf_record = self._extract_spf(result["records"]["TXT"])
        result["spf"] = spf_record
        self._audit_spf(spf_record, result)

        # 4. Analizar DMARC
        dmarc_record = self._extract_dmarc(result["records"]["DMARC"])
        result["dmarc"] = dmarc_record
        self._audit_dmarc(dmarc_record, result)

        # 5. Analizar MX
        self._audit_mx(result["records"]["MX"], result)

        return result

    def _query_doh(self, name: str, rtype: str) -> List[str]:
        type_num = self.RECORD_TYPES.get(rtype, 1)
        params = urllib.parse.urlencode({"name": name, "type": type_num})
        
        headers = {
            "Accept": "application/dns-json",
            "User-Agent": "PassiveSecurityRecon/1.0"
        }

        for provider in self.DOH_PROVIDERS:
            try:
                url = f"{provider}?{params}"
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.getcode() == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        answers = data.get("Answer", [])
                        results = []
                        for ans in answers:
                            data_val = ans.get("data", "").strip('"')
                            if data_val:
                                results.append(data_val)
                        if results:
                            return results
            except Exception:
                continue
        return []

    def _query_nslookup(self, name: str, rtype: str) -> List[str]:
        results = []
        try:
            cmd = ["nslookup", f"-type={rtype}", name]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=self.timeout)
            output = proc.stdout
            lines = output.splitlines()
            for line in lines:
                line = line.strip()
                if not line or "Server:" in line or "Address:" in line:
                    continue
                if rtype == "TXT" and "text =" in line:
                    parts = line.split("text =", 1)
                    if len(parts) > 1:
                        results.append(parts[1].strip().strip('"'))
                elif rtype == "MX" and "mail exchanger =" in line:
                    parts = line.split("mail exchanger =", 1)
                    if len(parts) > 1:
                        results.append(parts[1].strip())
                elif rtype == "NS" and "nameserver =" in line:
                    parts = line.split("nameserver =", 1)
                    if len(parts) > 1:
                        results.append(parts[1].strip())
                elif rtype in ["A", "AAAA"] and "Address:" not in line and "Aliases:" not in line:
                    # Formato nslookup windows
                    if line.startswith("Address:"):
                        addr = line.split("Address:", 1)[1].strip()
                        results.append(addr)
        except Exception:
            pass
        return results

    def _extract_spf(self, txt_records: List[str]) -> Optional[str]:
        for rec in txt_records:
            clean = rec.strip('"').strip()
            if clean.startswith("v=spf1"):
                return clean
        return None

    def _extract_dmarc(self, txt_records: List[str]) -> Optional[str]:
        for rec in txt_records:
            clean = rec.strip('"').strip()
            if "v=DMARC1" in clean or "v=dmarc1" in clean:
                return clean
        return None

    def _audit_spf(self, spf: Optional[str], result: Dict[str, Any]):
        if not spf:
            result["score"] -= 25
            result["findings"].append({
                "type": "MISSING_SPF_RECORD",
                "severity": "HIGH",
                "description": f"El dominio '{self.domain}' no tiene un registro SPF publicado.",
                "recommendation": "Publicar un registro TXT con SPF (v=spf1 ...) autorizando únicamente los servidores de correo legítimos."
            })
            return

        # Analizar mecanismos
        tokens = spf.split()
        all_qualifier = None
        for tok in tokens:
            if tok.endswith("all"):
                all_qualifier = tok
                break

        if all_qualifier in ["+all", "all"]:
            result["score"] -= 30
            result["findings"].append({
                "type": "PERMISSIVE_SPF_ALL",
                "severity": "HIGH",
                "description": f"El registro SPF utiliza directiva permisiva '{all_qualifier}', permitiendo que cualquier IP envíe correos en su nombre.",
                "recommendation": "Cambiar la directiva final a '~all' (SoftFail) o '-all' (HardFail)."
            })
        elif all_qualifier == "?all":
            result["score"] -= 15
            result["findings"].append({
                "type": "NEUTRAL_SPF_ALL",
                "severity": "MEDIUM",
                "description": "El registro SPF utiliza directiva neutral '?all', que no proporciona protección estricta contra suplantación.",
                "recommendation": "Migrar hacia '-all' o '~all' junto con política DMARC estricta."
            })
        elif all_qualifier in ["-all", "~all"]:
            result["findings"].append({
                "type": "SECURE_SPF_CONFIGURED",
                "severity": "GOOD",
                "description": f"Registro SPF activo y correctamente configurado con directiva restrictiva ({all_qualifier}).",
                "recommendation": "Mantener actualizado el listado de servidores autorizados."
            })

    def _audit_dmarc(self, dmarc: Optional[str], result: Dict[str, Any]):
        if not dmarc:
            result["score"] -= 25
            result["findings"].append({
                "type": "MISSING_DMARC_RECORD",
                "severity": "HIGH",
                "description": f"No se encontró registro DMARC en _dmarc.{self.domain}.",
                "recommendation": "Publicar un registro TXT en _dmarc con política mínima 'v=DMARC1; p=none; rua=mailto:...;'"
            })
            return

        # Analizar política 'p='
        tags = dict(item.strip().split("=", 1) for item in dmarc.split(";") if "=" in item)
        policy = tags.get("p", "").lower()

        if policy == "none":
            result["score"] -= 10
            result["findings"].append({
                "type": "DMARC_POLICY_MONITORING_ONLY",
                "severity": "MEDIUM",
                "description": "La política DMARC está configurada en 'p=none' (solo monitoreo; los correos no autorizados no son bloqueados).",
                "recommendation": "Tras analizar los reportes RUA, elevar la política a 'p=quarantine' o 'p=reject'."
            })
        elif policy in ["quarantine", "reject"]:
            result["findings"].append({
                "type": "DMARC_POLICY_ENFORCED",
                "severity": "GOOD",
                "description": f"Política DMARC estricta aplicada correctamente (p={policy}).",
                "recommendation": "Revisar periódicamente los reportes agregados recibidos."
            })
        else:
            result["score"] -= 15
            result["findings"].append({
                "type": "INVALID_DMARC_POLICY",
                "severity": "MEDIUM",
                "description": f"Directiva de política DMARC 'p={policy}' no estándar o inválida.",
                "recommendation": "Asegurar que p=reject, p=quarantine o p=none."
            })

    def _audit_mx(self, mx_records: List[str], result: Dict[str, Any]):
        if not mx_records:
            result["findings"].append({
                "type": "NO_MX_RECORDS",
                "severity": "INFO",
                "description": "No se detectaron registros MX directos. Si el dominio no gestiona correos, esto es esperado.",
                "recommendation": "Si el dominio envía correos, configurar registros MX correspondientes."
            })
        else:
            result["findings"].append({
                "type": "MX_RECORDS_DETECTED",
                "severity": "INFO",
                "description": f"Se detectaron {len(mx_records)} servidores de correo MX configurados.",
                "recommendation": "Verificar que todos los servidores MX apliquen cifrado TLS (STARTTLS)."
            })
