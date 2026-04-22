"""
WAF / CDN detection from HTTP response headers.

Detecta la presencia de firewalls de aplicación (WAF) y CDNs analizando
las cabeceras de respuesta. Útil para pentesters porque:
- Indica si hay una capa de protección adicional entre el attacker y el origin
- Un WAF que desaparece puede significar bypass o cambio de configuración
- Un WAF que aparece puede indicar que detectaron actividad sospechosa
"""
from __future__ import annotations

# (header_name_lower, value_substring_lower, waf_label)
# Si value_substring_lower == "", la presencia del header es suficiente.
WAF_SIGNATURES: list[tuple[str, str, str]] = [
    # Cloudflare — muy común, múltiples indicadores
    ("cf-ray",                    "",             "Cloudflare"),
    ("cf-cache-status",           "",             "Cloudflare"),
    ("cf-request-id",             "",             "Cloudflare"),
    ("server",                    "cloudflare",   "Cloudflare"),

    # AWS
    ("x-amz-cf-id",               "",             "AWS CloudFront"),
    ("x-amz-cf-pop",              "",             "AWS CloudFront"),
    ("via",                       "cloudfront",   "AWS CloudFront"),
    ("server",                    "awselb",       "AWS ELB"),
    ("server",                    "amazons3",     "AWS S3"),

    # Akamai
    ("x-akamai-transformed",      "",             "Akamai"),
    ("x-check-cacheable",         "",             "Akamai"),
    ("x-true-cache-key",          "",             "Akamai"),
    ("server",                    "akamaighost",  "Akamai"),

    # Fastly
    ("x-fastly-request-id",       "",             "Fastly"),
    ("x-served-by",               "cache-",       "Fastly"),

    # Imperva / Incapsula
    ("x-iinfo",                   "",             "Imperva Incapsula"),
    ("x-cdn",                     "incapsula",    "Imperva Incapsula"),
    ("server",                    "incapsula",    "Imperva Incapsula"),
    ("x-protected-by",            "incapsula",    "Imperva Incapsula"),

    # Sucuri
    ("x-sucuri-id",               "",             "Sucuri WAF"),
    ("x-sucuri-cache",            "",             "Sucuri WAF"),
    ("server",                    "sucuri",       "Sucuri WAF"),

    # Vercel
    ("x-vercel-id",               "",             "Vercel"),
    ("server",                    "vercel",       "Vercel"),

    # Netlify
    ("x-nf-request-id",           "",             "Netlify"),
    ("server",                    "netlify",      "Netlify"),

    # ModSecurity
    ("server",                    "mod_security", "ModSecurity"),

    # F5 / BIG-IP
    ("x-cnection",                "",             "F5 BIG-IP"),
    ("set-cookie",                "bigipserver",  "F5 BIG-IP"),
    ("set-cookie",                "ts0",          "F5 BIG-IP"),

    # Barracuda
    ("server",                    "barracuda",    "Barracuda WAF"),

    # Fortinet FortiWeb
    ("x-fw-hash",                 "",             "Fortinet FortiWeb"),
    ("server",                    "fortiweb",     "Fortinet FortiWeb"),

    # Radware
    ("x-rdwr-msg",                "",             "Radware AppWall"),
    ("server",                    "redirector",   "Radware"),

    # StackPath / Highwinds
    ("x-hw",                      "",             "StackPath CDN"),

    # Reblaze
    ("server",                    "reblaze",      "Reblaze WAF"),

    # Generic CDN indicators
    ("via",                       "varnish",      "Varnish Cache"),
    ("x-varnish",                 "",             "Varnish Cache"),
    ("x-cache",                   "hit",          "CDN Cache"),
]


def detect_waf(raw_headers: dict) -> str:
    """
    Retorna el nombre del WAF/CDN detectado, o string vacío si no se detecta.
    Devuelve el primer match (orden de especificidad en WAF_SIGNATURES).
    """
    norm = {k.lower(): v.lower() for k, v in raw_headers.items()}

    for header, substr, waf_name in WAF_SIGNATURES:
        val = norm.get(header, "")
        if not val:
            continue
        if not substr or substr in val:
            return waf_name

    return ""
