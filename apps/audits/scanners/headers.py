"""
HTTP headers + cookies scanner.

Comprueba la presencia y calidad de las cabeceras de seguridad
recomendadas por OWASP Secure Headers Project, y los flags de las
cookies devueltas en Set-Cookie.
"""
from __future__ import annotations

from http.cookies import SimpleCookie

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

# Headers obligatorios mínimos. La política de penalización vive aquí
# y no en scoring, porque es conocimiento de "cómo interpretar el header".
SECURITY_HEADERS = {
    "Content-Security-Policy": Severity.MEDIUM,
    "X-Content-Type-Options": Severity.LOW,
    "Referrer-Policy": Severity.LOW,
    "Permissions-Policy": Severity.LOW,
}

# HSTS solo tiene sentido en https.
HSTS_HEADER = "Strict-Transport-Security"

# X-Frame-Options o su equivalente moderno en CSP (frame-ancestors).
FRAME_OPTIONS_HEADER = "X-Frame-Options"


class HttpHeadersScanner(BaseScanner):
    name = "http_headers"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()

        if not context.has_http:
            result.raw = {"error": context.http_error or "Sin respuesta HTTP"}
            return result

        response = context.http_response
        assert response is not None  # para mypy
        headers = {k.title(): v for k, v in response.headers.items()}
        result.raw = {"status": response.status_code, "headers": headers}

        # --- Headers de seguridad principales ---
        for header_name, severity in SECURITY_HEADERS.items():
            if header_name not in headers:
                result.findings.append(
                    self.finding(
                        category=Category.HEADERS,
                        severity=severity,
                        title=f"Falta cabecera {header_name}",
                        description=(
                            f"La respuesta no incluye la cabecera {header_name}, "
                            "recomendada por OWASP."
                        ),
                        recommendation=_recommendation_for(header_name),
                        reference_url="https://owasp.org/www-project-secure-headers/",
                    )
                )

        # HSTS (solo si https)
        if context.target.is_https and HSTS_HEADER not in headers:
            result.findings.append(
                self.finding(
                    category=Category.HEADERS,
                    severity=Severity.MEDIUM,
                    title="Falta Strict-Transport-Security (HSTS)",
                    description=(
                        "El servidor no publica HSTS. Un atacante MITM "
                        "podría degradar la conexión a HTTP."
                    ),
                    recommendation=(
                        "Añade: "
                        "`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`"
                    ),
                )
            )

        # X-Frame-Options o CSP frame-ancestors
        csp = headers.get("Content-Security-Policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()
        if FRAME_OPTIONS_HEADER not in headers and not has_frame_ancestors:
            result.findings.append(
                self.finding(
                    category=Category.HEADERS,
                    severity=Severity.MEDIUM,
                    title="Sin protección contra clickjacking",
                    description=(
                        "Ni X-Frame-Options ni CSP frame-ancestors están presentes."
                    ),
                    recommendation=(
                        "Usa `X-Frame-Options: DENY` o añade "
                        "`frame-ancestors 'none'` a tu CSP."
                    ),
                )
            )

        # Disclosure del servidor
        server_header = headers.get("Server", "")
        if server_header and any(ch.isdigit() for ch in server_header):
            result.findings.append(
                self.finding(
                    category=Category.HEADERS,
                    severity=Severity.LOW,
                    title="Cabecera Server revela la versión",
                    description=f"Server: {server_header}",
                    recommendation="Oculta la versión del servidor web.",
                    evidence={"server": server_header},
                )
            )
        if "X-Powered-By" in headers:
            result.findings.append(
                self.finding(
                    category=Category.HEADERS,
                    severity=Severity.LOW,
                    title="Cabecera X-Powered-By expuesta",
                    description=f"X-Powered-By: {headers['X-Powered-By']}",
                    recommendation="Elimina X-Powered-By para no filtrar el stack.",
                )
            )

        # --- Cookies ---
        self._scan_cookies(response, context, result)

        return result

    def _scan_cookies(self, response, context, result: ScanResult) -> None:
        set_cookie_headers = response.headers.get_list("Set-Cookie") if hasattr(
            response.headers, "get_list"
        ) else response.raw.headers.getlist("Set-Cookie") if hasattr(
            response.raw, "headers"
        ) else [response.headers.get("Set-Cookie", "")]

        set_cookie_headers = [h for h in set_cookie_headers if h]
        cookies_evidence = []

        for raw_cookie in set_cookie_headers:
            cookie = SimpleCookie()
            try:
                cookie.load(raw_cookie)
            except Exception:
                continue

            for name, morsel in cookie.items():
                flags = {
                    "httponly": "httponly" in raw_cookie.lower(),
                    "secure": "secure" in raw_cookie.lower(),
                    "samesite": "samesite" in raw_cookie.lower(),
                }
                cookies_evidence.append({"name": name, **flags})

                if not flags["httponly"]:
                    result.findings.append(
                        self.finding(
                            category=Category.COOKIES,
                            severity=Severity.MEDIUM,
                            title=f"Cookie '{name}' sin HttpOnly",
                            description=(
                                "JavaScript puede leer la cookie, lo que permite "
                                "robarla con XSS."
                            ),
                            recommendation="Añade el flag HttpOnly.",
                            evidence={"cookie": name},
                        )
                    )
                if context.target.is_https and not flags["secure"]:
                    result.findings.append(
                        self.finding(
                            category=Category.COOKIES,
                            severity=Severity.HIGH,
                            title=f"Cookie '{name}' sin Secure en sitio HTTPS",
                            description=(
                                "La cookie puede enviarse por HTTP, exponiéndola."
                            ),
                            recommendation="Añade el flag Secure.",
                            evidence={"cookie": name},
                        )
                    )
                if not flags["samesite"]:
                    result.findings.append(
                        self.finding(
                            category=Category.COOKIES,
                            severity=Severity.LOW,
                            title=f"Cookie '{name}' sin SameSite",
                            description="Sin SameSite la cookie es más vulnerable a CSRF.",
                            recommendation="Usa SameSite=Lax o Strict.",
                            evidence={"cookie": name},
                        )
                    )

        result.raw["cookies"] = cookies_evidence


def _recommendation_for(header_name: str) -> str:
    table = {
        "Content-Security-Policy": (
            "Define una CSP estricta. Arranca con "
            "`default-src 'self'; object-src 'none'` y afina."
        ),
        "X-Content-Type-Options": "Añade `X-Content-Type-Options: nosniff`.",
        "Referrer-Policy": "Añade `Referrer-Policy: strict-origin-when-cross-origin`.",
        "Permissions-Policy": (
            "Añade `Permissions-Policy: camera=(), microphone=(), geolocation=()`."
        ),
    }
    return table.get(header_name, "")
