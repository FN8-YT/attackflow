"""
Scanner de fingerprinting de tecnologías.

Detecta el stack tecnológico del objetivo analizando:
- Headers HTTP (Server, X-Powered-By, X-AspNet-Version, etc.)
- Cookies conocidas (PHPSESSID, JSESSIONID, csrftoken, etc.)
- Patrones en el HTML (generadores, frameworks CSS/JS, meta tags)

Es pasivo — no envía payloads, solo lee la respuesta HTTP prefetch.
"""
from __future__ import annotations

import re

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

# Mapeo header → tecnología.
HEADER_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "server": [
        ("apache", "Apache HTTP Server"),
        ("nginx", "Nginx"),
        ("microsoft-iis", "Microsoft IIS"),
        ("cloudflare", "Cloudflare"),
        ("litespeed", "LiteSpeed"),
        ("openresty", "OpenResty (Nginx)"),
        ("gunicorn", "Gunicorn (Python)"),
        ("uvicorn", "Uvicorn (Python ASGI)"),
        ("express", "Express.js (Node)"),
        ("caddy", "Caddy"),
    ],
    "x-powered-by": [
        ("php", "PHP"),
        ("asp.net", "ASP.NET"),
        ("express", "Express.js"),
        ("next.js", "Next.js"),
        ("nuxt", "Nuxt.js"),
    ],
}

# Cookies conocidas → tecnología.
COOKIE_SIGNATURES: list[tuple[str, str]] = [
    ("phpsessid", "PHP"),
    ("jsessionid", "Java (Servlet/Spring)"),
    ("asp.net_sessionid", "ASP.NET"),
    ("csrftoken", "Django"),
    ("_rails_session", "Ruby on Rails"),
    ("laravel_session", "Laravel (PHP)"),
    ("connect.sid", "Express.js / Connect"),
    ("ci_session", "CodeIgniter (PHP)"),
    ("wp-settings-", "WordPress"),
]

# Patrones en HTML.
HTML_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, tech_name, evidence_key)
    (r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)', "CMS/Generator", "generator"),
    (r'wp-content/', "WordPress", "wp_path"),
    (r'wp-includes/', "WordPress", "wp_path"),
    (r'/sites/default/files', "Drupal", "drupal_path"),
    (r'Joomla!', "Joomla", "joomla_marker"),
    (r'cdn\.shopify\.com', "Shopify", "shopify_cdn"),
    (r'static\.squarespace\.com', "Squarespace", "squarespace_cdn"),
    (r'react', "React.js", "react_marker"),
    (r'__next', "Next.js", "nextjs_marker"),
    (r'__nuxt', "Nuxt.js", "nuxt_marker"),
    (r'ng-version=', "Angular", "angular_marker"),
    (r'data-vue-', "Vue.js", "vue_marker"),
    (r'bootstrap\.min\.(css|js)', "Bootstrap", "bootstrap_asset"),
    (r'tailwindcss', "Tailwind CSS", "tailwind_marker"),
    (r'jquery[\.-](\d)', "jQuery", "jquery_asset"),
]


class TechScanner(BaseScanner):
    name = "tech"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        techs: dict[str, dict] = {}  # name → {source, detail}

        if not context.has_http:
            result.raw = {"error": context.http_error or "Sin respuesta HTTP"}
            return result

        resp = context.http_response
        headers = {k.lower(): v for k, v in resp.headers.items()}
        html = context.body_text.lower()

        # --- Headers ---
        for header_name, signatures in HEADER_SIGNATURES.items():
            value = headers.get(header_name, "").lower()
            if not value:
                continue
            for keyword, tech_name in signatures:
                if keyword in value:
                    techs[tech_name] = {
                        "source": f"header:{header_name}",
                        "raw_value": headers.get(header_name, ""),
                    }

        # Header de versión (ASP.NET, etc.)
        for h in ("x-aspnet-version", "x-aspnetmvc-version"):
            val = headers.get(h)
            if val:
                techs[f"ASP.NET ({h})"] = {"source": f"header:{h}", "version": val}

        # --- Cookies ---
        cookies = resp.headers.get("set-cookie", "").lower()
        for cookie_key, tech_name in COOKIE_SIGNATURES:
            if cookie_key in cookies:
                techs.setdefault(tech_name, {
                    "source": f"cookie:{cookie_key}",
                })

        # --- HTML patterns ---
        for pattern, tech_name, evidence_key in HTML_PATTERNS:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                techs.setdefault(tech_name, {
                    "source": "html",
                    evidence_key: match.group(0)[:120],
                })

        sorted_techs = dict(sorted(techs.items()))
        result.raw = {
            "technologies_found": len(sorted_techs),
            "technologies": sorted_techs,
        }

        if sorted_techs:
            result.findings.append(
                self.finding(
                    category=Category.RECON,
                    severity=Severity.INFO,
                    title=f"{len(sorted_techs)} tecnologías detectadas",
                    description=(
                        "Se identificaron las siguientes tecnologías: "
                        + ", ".join(sorted_techs.keys()) + "."
                    ),
                    evidence=sorted_techs,
                    recommendation=(
                        "Verifica que las versiones expuestas estén actualizadas. "
                        "Considera ocultar headers de versión (Server, X-Powered-By) "
                        "para reducir el fingerprinting."
                    ),
                )
            )

        # Alerta por version disclosure en headers.
        disclosed = []
        for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
            val = headers.get(h)
            if val and re.search(r'\d+\.\d+', val):
                disclosed.append(f"{h}: {val}")

        if disclosed:
            result.findings.append(
                self.finding(
                    category=Category.RECON,
                    severity=Severity.LOW,
                    title="Versiones de software expuestas en headers",
                    description=(
                        "Los siguientes headers revelan versiones concretas del "
                        "software, lo que facilita buscar exploits conocidos."
                    ),
                    evidence={"headers": disclosed},
                    recommendation=(
                        "Configura el servidor para no revelar versiones. "
                        "Ej: ServerTokens Prod (Apache), server_tokens off (Nginx)."
                    ),
                )
            )

        return result
