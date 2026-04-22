"""
Technology detection from HTTP response headers, cookies and HTML body.

Detecta el stack tecnológico de un target analizando:
- Response headers (Server, X-Powered-By, X-Generator, etc.)
- Cookies (PHPSESSID → PHP, JSESSIONID → Java, etc.)
- HTML body (meta generators, JS framework signatures, CDN patterns)
"""
from __future__ import annotations

import re

# ── Header signatures ──────────────────────────────────────────────────────────
# (header_name_lower, [(substring_lower, tech_label), ...])
# Si substring_lower == "", la presencia del header basta.
HEADER_SIGNATURES: list[tuple[str, list[tuple[str, str]]]] = [
    ("server", [
        ("cloudflare", "Cloudflare"),
        ("nginx",      "Nginx"),
        ("apache",     "Apache"),
        ("litespeed",  "LiteSpeed"),
        ("openresty",  "OpenResty"),
        ("iis",        "IIS"),
        ("gunicorn",   "Gunicorn"),
        ("uvicorn",    "Uvicorn"),
        ("caddy",      "Caddy"),
        ("lighttpd",   "lighttpd"),
        ("tomcat",     "Apache Tomcat"),
        ("jetty",      "Jetty"),
    ]),
    ("x-powered-by", [
        ("php",        "PHP"),
        ("asp.net",    "ASP.NET"),
        ("express",    "Express.js"),
        ("next.js",    "Next.js"),
        ("ruby",       "Ruby on Rails"),
        ("django",     "Django"),
    ]),
    ("x-generator", [
        ("wordpress",  "WordPress"),
        ("drupal",     "Drupal"),
        ("joomla",     "Joomla"),
        ("hugo",       "Hugo"),
        ("gatsby",     "Gatsby"),
        ("jekyll",     "Jekyll"),
        ("ghost",      "Ghost"),
    ]),
    ("x-drupal-cache",    [("", "Drupal")]),
    ("x-drupal-dynamic",  [("", "Drupal")]),
    ("x-pingback",        [("xmlrpc.php", "WordPress")]),
    ("x-wp-super-cache",  [("", "WordPress")]),
    ("x-shopify-stage",   [("", "Shopify")]),
    ("x-ghost-cache",     [("", "Ghost")]),
    ("x-wix-dispatcher",  [("", "Wix")]),
    ("x-squarespace-serviced-by", [("", "Squarespace")]),
]

# ── Cookie name signatures ─────────────────────────────────────────────────────
COOKIE_SIGNATURES: list[tuple[str, str]] = [
    ("PHPSESSID",        "PHP"),
    ("ASP.NET_SessionId", "ASP.NET"),
    ("JSESSIONID",       "Java"),
    ("ci_session",       "CodeIgniter"),
    ("laravel_session",  "Laravel"),
    ("_session_id",      "Ruby on Rails"),
    ("connect.sid",      "Express.js"),
    ("django",           "Django"),
    ("wordpress_logged", "WordPress"),
    ("wp-settings",      "WordPress"),
    ("PrestaShop",       "PrestaShop"),
]

# ── HTML body patterns ─────────────────────────────────────────────────────────
HTML_SIGNATURES: list[tuple[str, str]] = [
    (r'<meta[^>]+generator[^>]+wordpress',   "WordPress"),
    (r'wp-content|wp-includes',              "WordPress"),
    (r'drupal\.settings|\/drupal\.js',       "Drupal"),
    (r'joomla!',                             "Joomla"),
    (r'typo3\.org',                          "TYPO3"),
    (r'cdn\.shopify\.com|shopify\.com\/s',   "Shopify"),
    (r'bigcommerce\.com',                    "BigCommerce"),
    (r'woocommerce',                         "WooCommerce"),
    (r'magento',                             "Magento"),
    (r'prestashop',                          "PrestaShop"),
    (r'__next|_next\/static\/',              "Next.js"),
    (r'__nuxt|_nuxt\/',                      "Nuxt.js"),
    (r'ng-version=|angular\.min\.js',        "Angular"),
    (r'data-reactroot|react\.production',    "React"),
    (r'vue\.runtime|__vue_store__',          "Vue.js"),
    (r'gatsby-plugin|gatsby-chunk',         "Gatsby"),
    (r'svelte',                              "Svelte"),
    (r'cdn\.jsdelivr\.net\/npm\/bootstrap',  "Bootstrap"),
    (r'tailwind\.css|class="[^"]*tw-',      "TailwindCSS"),
    (r'jquery\.min\.js|jquery-\d',           "jQuery"),
    (r'cdn\.jsdelivr\.net\/npm\/bulma',      "Bulma"),
    (r'fontawesome',                         "Font Awesome"),
    (r'google-analytics\.com|gtag\(',       "Google Analytics"),
    (r'googletagmanager\.com',               "Google Tag Manager"),
]


def detect_technologies(
    raw_headers: dict,
    body_snippet: str,
    cookies: dict,
) -> list[str]:
    """
    Detecta tecnologías del stack del target.

    Args:
        raw_headers: Todos los response headers (key/value originales).
        body_snippet: Primeros ~20KB del body HTML.
        cookies: Dict de cookies {name: value}.

    Returns:
        Lista ordenada y deduplicada de tecnologías detectadas,
        con versión cuando es posible extraerla (e.g. "PHP/8.1").
    """
    found: set[str] = set()

    # Normalizar headers a minúsculas para comparar
    norm_headers = {k.lower(): v for k, v in raw_headers.items()}

    for header_name, patterns in HEADER_SIGNATURES:
        raw_val = norm_headers.get(header_name, "")
        if not raw_val:
            continue
        val_lower = raw_val.lower()

        for substr, tech in patterns:
            if not substr or substr in val_lower:
                # Intentar extraer versión para Server y X-Powered-By
                if header_name in ("server", "x-powered-by"):
                    versioned = _with_version(raw_val, tech)
                    found.add(versioned)
                else:
                    found.add(tech)
                break  # solo primer match por header

    # Cookies
    norm_cookies = {k.lower() for k in cookies}
    for cookie_name, tech in COOKIE_SIGNATURES:
        if cookie_name.lower() in norm_cookies:
            found.add(tech)

    # HTML body
    body_lower = body_snippet[:20_000].lower()
    for pattern, tech in HTML_SIGNATURES:
        if tech not in found and re.search(pattern, body_lower, re.IGNORECASE):
            found.add(tech)

    return sorted(found)


def _with_version(header_value: str, tech: str) -> str:
    """Extrae la versión mayor.menor del header value, e.g. 'PHP/8.1.3' → 'PHP/8.1'."""
    pattern = re.compile(re.escape(tech) + r"[/\s]+(\d+\.\d+)", re.IGNORECASE)
    m = pattern.search(header_value)
    if m:
        return f"{tech}/{m.group(1)}"
    return tech
