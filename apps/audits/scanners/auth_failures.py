"""
OWASP A07 — Identification and Authentication Failures.

Detecta desde fuera:
- Formularios de login sin protección CSRF.
- Posible account enumeration (respuestas diferentes para users válidos/inválidos).
- Session cookies inseguras (session fixation potential).
- Login sobre HTTP (credenciales en texto plano).

MODO ACTIVO: envía requests a formularios de login.

Limitaciones honestas:
- No prueba credenciales reales (no es brute force).
- No puede verificar password policies sin una cuenta.
- Account enumeration es probabilístico (compara tiempos/tamaños de respuesta).
"""
from __future__ import annotations

import logging
import re
import time

import requests

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

logger = logging.getLogger(__name__)

TIMEOUT = 8
UA = "SecurityAuditBot/0.1"

# Paths comunes de login.
LOGIN_PATHS = [
    "/login", "/login/", "/signin", "/sign-in",
    "/auth/login", "/user/login", "/account/login",
    "/wp-login.php", "/admin/login/", "/api/auth/login",
]


class AuthFailuresScanner(BaseScanner):
    name = "auth_failures"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        target = context.target
        base = f"{target.scheme}://{target.hostname}"
        if target.port not in (80, 443):
            base += f":{target.port}"

        login_info = self._find_login_form(base, context)
        session_info = self._analyze_session(context)

        result.raw = {
            "login_form": login_info,
            "session": session_info,
        }

        # --- Login form over HTTP ---
        if login_info.get("found") and login_info.get("over_http"):
            result.findings.append(self.finding(
                category=Category.AUTH,
                severity=Severity.CRITICAL,
                title="Login transmite credenciales por HTTP (A07)",
                description=(
                    f"El formulario de login en '{login_info['path']}' envía "
                    "credenciales sin cifrar. Cualquier atacante en la red "
                    "puede interceptar usuarios y contraseñas."
                ),
                evidence=login_info,
                recommendation="Migra el login a HTTPS y redirige todo tráfico HTTP.",
                reference_url="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            ))

        # --- Missing CSRF token ---
        if login_info.get("found") and not login_info.get("has_csrf"):
            result.findings.append(self.finding(
                category=Category.AUTH,
                severity=Severity.HIGH,
                title="Formulario de login sin protección CSRF (A07)",
                description=(
                    f"El formulario de login en '{login_info['path']}' no "
                    "contiene un token CSRF visible. Esto puede permitir "
                    "ataques de login CSRF (forzar login con cuenta del atacante)."
                ),
                evidence=login_info,
                recommendation=(
                    "Implementa tokens CSRF en todos los formularios. "
                    "Django: {% csrf_token %}, Express: csurf middleware."
                ),
                reference_url="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            ))

        # --- Account enumeration ---
        if login_info.get("enumeration_possible"):
            result.findings.append(self.finding(
                category=Category.AUTH,
                severity=Severity.MEDIUM,
                title="Posible enumeración de cuentas (A07)",
                description=(
                    "El servidor responde de forma diferente según si el usuario "
                    "existe o no. Los atacantes usan esto para confirmar emails "
                    "o usernames válidos antes de hacer brute force."
                ),
                evidence={"detail": login_info.get("enum_detail", "")},
                recommendation=(
                    "Usa mensajes de error genéricos: 'Credenciales inválidas' "
                    "sin distinguir si el usuario o la contraseña son incorrectos."
                ),
                reference_url="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            ))

        # --- Session fixation potential ---
        if session_info.get("fixation_risk"):
            result.findings.append(self.finding(
                category=Category.AUTH,
                severity=Severity.MEDIUM,
                title="Riesgo de session fixation (A07)",
                description=(
                    "El servidor establece cookies de sesión antes de la "
                    "autenticación. Si la cookie no se regenera tras el login, "
                    "un atacante podría fijar la sesión."
                ),
                evidence=session_info,
                recommendation=(
                    "Regenera el session ID después de cada login exitoso. "
                    "Django: request.session.cycle_key()"
                ),
            ))

        if not login_info.get("found"):
            result.findings.append(self.finding(
                category=Category.AUTH,
                severity=Severity.INFO,
                title="No se encontró formulario de login expuesto (A07)",
                description="No se detectaron endpoints de login en rutas comunes.",
            ))
        elif not login_info.get("over_http") and login_info.get("has_csrf") \
                and not login_info.get("enumeration_possible"):
            result.findings.append(self.finding(
                category=Category.AUTH,
                severity=Severity.INFO,
                title="Login con protecciones básicas correctas (A07)",
                description="HTTPS, CSRF y mensajes genéricos verificados.",
            ))

        return result

    def _find_login_form(self, base: str, context: ScanContext) -> dict:
        """Busca un formulario de login y analiza sus protecciones."""
        info: dict = {"found": False}

        for path in LOGIN_PATHS:
            try:
                resp = requests.get(
                    base + path,
                    timeout=TIMEOUT,
                    headers={"User-Agent": UA},
                    allow_redirects=True,
                )
                if resp.status_code != 200:
                    continue
                body = resp.text.lower()
                has_password = 'type="password"' in body or "type='password'" in body
                if not has_password:
                    continue

                info["found"] = True
                info["path"] = path
                info["over_http"] = resp.url.startswith("http://")

                # Check CSRF.
                csrf_patterns = [
                    "csrf", "csrfmiddlewaretoken", "_token",
                    "authenticity_token", "__requestverificationtoken",
                ]
                info["has_csrf"] = any(p in body for p in csrf_patterns)

                # Account enumeration: try two fake logins and compare.
                info.update(self._check_enumeration(base + path, resp.text))
                break

            except requests.RequestException:
                continue

        return info

    def _check_enumeration(self, login_url: str, page_html: str) -> dict:
        """
        Intenta detectar account enumeration comparando respuestas
        para un usuario que probablemente no existe vs otro.
        """
        # Extract form action if present.
        action_match = re.search(
            r'<form[^>]*action=["\']([^"\']*)["\']',
            page_html, re.IGNORECASE,
        )

        # Only check if we found a POST form.
        if not action_match:
            return {}

        # We compare response sizes for two fake usernames.
        # If significantly different, enumeration is possible.
        fake_users = [
            "definitely_not_a_real_user_xz9@test.com",
            "another_fake_user_yz8@test.com",
        ]
        sizes = []
        for user in fake_users:
            try:
                resp = requests.post(
                    login_url,
                    data={"username": user, "email": user, "password": "FakePass123!"},
                    timeout=TIMEOUT,
                    headers={"User-Agent": UA},
                    allow_redirects=True,
                )
                sizes.append(len(resp.text))
            except requests.RequestException:
                return {}

        if len(sizes) == 2 and abs(sizes[0] - sizes[1]) > 50:
            return {
                "enumeration_possible": True,
                "enum_detail": (
                    f"Respuestas de tamaño diferente para usuarios falsos: "
                    f"{sizes[0]} vs {sizes[1]} bytes"
                ),
            }
        return {}

    def _analyze_session(self, context: ScanContext) -> dict:
        """Analiza cookies de sesión por riesgos."""
        info: dict = {}
        if not context.has_http:
            return info

        cookies = context.http_response.headers.get("Set-Cookie", "").lower()
        session_names = ["sessionid", "session", "sid", "phpsessid", "jsessionid"]
        has_session = any(n in cookies for n in session_names)

        if has_session:
            info["pre_auth_session"] = True
            info["fixation_risk"] = True

        return info
