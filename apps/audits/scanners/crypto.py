"""
OWASP A02 — Cryptographic Failures.

Detecta problemas criptográficos analizando la respuesta HTTP:
- Cookies sin flags de seguridad (Secure, HttpOnly, SameSite).
- Mixed content (recursos HTTP en páginas HTTPS).
- HSTS débil o ausente (complementa el headers scanner con análisis profundo).
- Formularios que envían datos a endpoints HTTP (cleartext).

Es 100% pasivo — solo analiza la respuesta HTTP prefetch.
"""
from __future__ import annotations

import re

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult


class CryptoScanner(BaseScanner):
    name = "crypto"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()

        if not context.has_http:
            result.raw = {"error": context.http_error or "Sin respuesta HTTP"}
            return result

        resp = context.http_response
        is_https = context.target.scheme == "https"
        cookies = self._analyze_cookies(resp, is_https)
        mixed = self._check_mixed_content(context.body_text) if is_https else []
        hsts = self._analyze_hsts(resp, is_https)
        forms = self._check_cleartext_forms(context.body_text, is_https)

        result.raw = {
            "insecure_cookies": len(cookies),
            "mixed_content": len(mixed),
            "hsts": hsts,
            "cleartext_forms": len(forms),
        }

        # --- Cookie findings ---
        for c in cookies:
            issues = c["issues"]
            if "no_secure" in issues:
                result.findings.append(self.finding(
                    category=Category.CRYPTO,
                    severity=Severity.MEDIUM,
                    title=f"Cookie '{c['name']}' sin flag Secure (A02)",
                    description=(
                        f"La cookie '{c['name']}' no tiene el flag Secure, "
                        "lo que permite que se transmita por HTTP en texto plano."
                    ),
                    evidence=c,
                    recommendation="Añade el flag Secure a todas las cookies sensibles.",
                    reference_url="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                ))
            if "no_httponly" in issues:
                result.findings.append(self.finding(
                    category=Category.CRYPTO,
                    severity=Severity.MEDIUM,
                    title=f"Cookie '{c['name']}' sin flag HttpOnly (A02)",
                    description=(
                        f"La cookie '{c['name']}' es accesible desde JavaScript. "
                        "Un ataque XSS podría robar su valor."
                    ),
                    evidence=c,
                    recommendation="Añade HttpOnly a cookies de sesión.",
                    reference_url="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                ))
            if "no_samesite" in issues:
                result.findings.append(self.finding(
                    category=Category.CRYPTO,
                    severity=Severity.LOW,
                    title=f"Cookie '{c['name']}' sin SameSite (A02)",
                    description=(
                        f"La cookie '{c['name']}' no define SameSite, "
                        "lo que la hace vulnerable a CSRF en navegadores antiguos."
                    ),
                    evidence=c,
                    recommendation="Añade SameSite=Lax o SameSite=Strict.",
                ))

        # --- Mixed content ---
        if mixed:
            result.findings.append(self.finding(
                category=Category.CRYPTO,
                severity=Severity.MEDIUM,
                title=f"{len(mixed)} recursos cargados por HTTP (mixed content) (A02)",
                description=(
                    "La página HTTPS carga recursos por HTTP sin cifrar. "
                    "Un atacante MitM podría inyectar contenido malicioso."
                ),
                evidence={"resources": mixed[:15]},
                recommendation="Carga todos los recursos por HTTPS.",
                reference_url="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            ))

        # --- HSTS ---
        if is_https and hsts.get("missing"):
            result.findings.append(self.finding(
                category=Category.CRYPTO,
                severity=Severity.MEDIUM,
                title="HSTS (Strict-Transport-Security) ausente (A02)",
                description=(
                    "El servidor HTTPS no envía el header HSTS. "
                    "Los usuarios pueden ser downgraded a HTTP por un atacante."
                ),
                evidence=hsts,
                recommendation=(
                    "Añade: Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains; preload"
                ),
                reference_url="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            ))
        elif is_https and hsts.get("weak_max_age"):
            result.findings.append(self.finding(
                category=Category.CRYPTO,
                severity=Severity.LOW,
                title="HSTS con max-age demasiado corto (A02)",
                description=(
                    f"HSTS max-age es {hsts.get('max_age')} segundos "
                    f"({hsts.get('max_age', 0) // 86400} días). "
                    "Se recomienda mínimo 1 año (31536000)."
                ),
                evidence=hsts,
                recommendation="Incrementa max-age a 31536000 (1 año).",
            ))

        # --- Cleartext forms ---
        for f in forms:
            result.findings.append(self.finding(
                category=Category.CRYPTO,
                severity=Severity.HIGH,
                title="Formulario envía datos por HTTP (A02)",
                description=(
                    f"Un formulario con action='{f['action']}' envía datos "
                    "sin cifrar. Credenciales o datos sensibles pueden ser "
                    "interceptados."
                ),
                evidence=f,
                recommendation="Cambia el action del formulario a HTTPS.",
                reference_url="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            ))

        if not cookies and not mixed and not forms \
                and not hsts.get("missing") and not hsts.get("weak_max_age"):
            result.findings.append(self.finding(
                category=Category.CRYPTO,
                severity=Severity.INFO,
                title="No se detectaron fallos criptográficos (A02)",
                description="Cookies, HSTS, mixed content y formularios verificados.",
            ))

        return result

    def _analyze_cookies(self, resp, is_https: bool) -> list[dict]:
        """Analiza cada Set-Cookie por flags de seguridad."""
        insecure = []
        raw_cookies = resp.headers.get("Set-Cookie", "")
        if not raw_cookies:
            return []

        # Headers puede tener múltiples Set-Cookie.
        for header_val in resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else [raw_cookies]:
            parts = header_val.split(";")
            if not parts:
                continue
            name = parts[0].split("=")[0].strip()
            flags_lower = header_val.lower()
            issues = []
            if is_https and "secure" not in flags_lower:
                issues.append("no_secure")
            if "httponly" not in flags_lower:
                issues.append("no_httponly")
            if "samesite" not in flags_lower:
                issues.append("no_samesite")
            if issues:
                insecure.append({"name": name, "issues": issues})
        return insecure

    def _check_mixed_content(self, html: str) -> list[str]:
        """Busca recursos cargados por HTTP en una página HTTPS."""
        pattern = r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']'
        matches = re.findall(pattern, html, re.IGNORECASE)
        urls = []
        for m in matches:
            url = re.search(r'http://[^"\']+', m)
            if url:
                urls.append(url.group(0)[:200])
        return list(set(urls))

    def _analyze_hsts(self, resp, is_https: bool) -> dict:
        """Analiza la calidad del header HSTS."""
        if not is_https:
            return {"not_https": True}
        hsts_val = resp.headers.get("Strict-Transport-Security", "")
        if not hsts_val:
            return {"missing": True}
        info: dict = {"value": hsts_val}
        match = re.search(r"max-age=(\d+)", hsts_val)
        if match:
            max_age = int(match.group(1))
            info["max_age"] = max_age
            if max_age < 15768000:  # < 6 meses
                info["weak_max_age"] = True
        info["includeSubDomains"] = "includesubdomains" in hsts_val.lower()
        info["preload"] = "preload" in hsts_val.lower()
        return info

    def _check_cleartext_forms(self, html: str, is_https: bool) -> list[dict]:
        """Busca formularios que envían a URLs HTTP."""
        if not is_https:
            return []
        forms = re.findall(
            r'<form[^>]*action\s*=\s*["\']?(http://[^"\'>\s]+)',
            html, re.IGNORECASE,
        )
        return [{"action": url[:200]} for url in set(forms)]
