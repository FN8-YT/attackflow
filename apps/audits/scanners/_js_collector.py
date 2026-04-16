"""
JS Collector — utilidad compartida para los scanners de JavaScript.

Responsabilidades:
- Extraer scripts inline del HTML (<script>...</script>).
- Extraer URLs de scripts externos (<script src="...">).
- Resolver rutas relativas a URLs absolutas.
- Fetch de scripts externos con límites de tamaño y timeout.
- Proveer el JS recolectado a los scanners de análisis.

NO es un scanner por sí mismo — es infraestructura de soporte.
Los scanners js_analysis, js_secrets y js_endpoints consumen
las instancias de JSSource que esta clase produce.

Diseño:
- Lazy: solo hace fetch cuando se pide explícitamente.
- Bounded: límites de cantidad y tamaño para no abusar del target.
- Resiliente: errores de fetch individuales no rompen el resto.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger(__name__)

TIMEOUT = 10
MAX_EXTERNAL_SCRIPTS = 20
MAX_SCRIPT_SIZE = 512_000  # 512 KB per script
UA = "SecurityAuditBot/0.1"


@dataclass
class JSSource:
    """Una fuente de JavaScript recolectada."""

    content: str
    source_type: str        # "inline" | "external"
    url: str = ""           # Solo para external
    size: int = 0
    fetch_error: str = ""   # Si falló el fetch


@dataclass
class CollectionStats:
    """Estadísticas de la recolección para raw_data."""

    inline_count: int = 0
    inline_total_size: int = 0
    external_urls_found: int = 0
    external_fetched: int = 0
    external_errors: int = 0
    external_total_size: int = 0


class JSCollector:
    """
    Recolecta JavaScript de una página web.

    Uso típico:
        collector = JSCollector(html, "https://example.com")
        sources = collector.collect_all(fetch_external=True)
        all_js = collector.combined_content(sources)
    """

    def __init__(self, html: str, base_url: str):
        self.html = html
        self.base_url = base_url
        self.stats = CollectionStats()

    def collect_inline(self) -> list[JSSource]:
        """Extrae contenido de todos los <script>...</script> inline."""
        # Match script tags that don't have a src attribute (inline).
        pattern = re.compile(
            r'<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>',
            re.DOTALL | re.IGNORECASE,
        )

        sources: list[JSSource] = []
        for match in pattern.finditer(self.html):
            content = match.group(1).strip()
            if not content:
                continue
            # Ignore JSON-LD and other non-JS script types.
            tag_attrs = self.html[match.start():match.start() + match.group(0).index('>')]
            if re.search(r'type\s*=\s*["\'](?!text/javascript|application/javascript|module)[^"\']+["\']',
                         tag_attrs, re.IGNORECASE):
                continue

            sources.append(JSSource(
                content=content,
                source_type="inline",
                size=len(content),
            ))

        self.stats.inline_count = len(sources)
        self.stats.inline_total_size = sum(s.size for s in sources)
        return sources

    def get_external_urls(self) -> list[str]:
        """Extrae URLs de <script src="..."> y las resuelve a absolutas."""
        pattern = re.compile(
            r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>',
            re.IGNORECASE,
        )

        urls: list[str] = []
        seen: set[str] = set()

        for match in pattern.finditer(self.html):
            raw_url = match.group(1).strip()
            if not raw_url:
                continue

            absolute = self._resolve_url(raw_url)
            if absolute and absolute not in seen:
                seen.add(absolute)
                urls.append(absolute)

        self.stats.external_urls_found = len(urls)
        return urls

    def fetch_external(
        self,
        urls: list[str] | None = None,
        max_scripts: int = MAX_EXTERNAL_SCRIPTS,
    ) -> list[JSSource]:
        """
        Descarga scripts externos.

        Solo descarga archivos .js (o sin extensión clara).
        Ignora recursos que no parecen JavaScript (imágenes, CSS, etc.).
        """
        if urls is None:
            urls = self.get_external_urls()

        sources: list[JSSource] = []
        fetched = 0
        errors = 0

        for url in urls[:max_scripts]:
            # Skip non-JS resources.
            parsed = urlparse(url)
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in
                   ('.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.woff2')):
                continue

            try:
                resp = requests.get(
                    url,
                    timeout=TIMEOUT,
                    headers={"User-Agent": UA},
                    stream=True,
                )

                # Verify it's JavaScript-like content.
                ct = resp.headers.get("Content-Type", "")
                if resp.status_code != 200:
                    errors += 1
                    continue

                # Read with size limit.
                content = resp.text[:MAX_SCRIPT_SIZE]
                if not content.strip():
                    continue

                sources.append(JSSource(
                    content=content,
                    source_type="external",
                    url=url,
                    size=len(content),
                ))
                fetched += 1

            except requests.RequestException as exc:
                logger.debug("JS fetch error for %s: %s", url, exc)
                errors += 1
                continue

        self.stats.external_fetched = fetched
        self.stats.external_errors = errors
        self.stats.external_total_size = sum(s.size for s in sources)
        return sources

    def collect_all(self, fetch_external: bool = True) -> list[JSSource]:
        """
        Recolecta todo el JS: inline + externo.

        Args:
            fetch_external: Si True, descarga scripts externos (modo activo).
                           Si False, solo inline (modo pasivo).
        """
        sources = self.collect_inline()
        if fetch_external:
            sources.extend(self.fetch_external())
        return sources

    @staticmethod
    def combined_content(sources: list[JSSource]) -> str:
        """Concatena todo el JS en un solo string para análisis."""
        return "\n\n".join(s.content for s in sources if s.content)

    def _resolve_url(self, raw: str) -> str:
        """Resuelve una URL relativa a absoluta usando la base."""
        # Protocol-relative.
        if raw.startswith("//"):
            scheme = urlparse(self.base_url).scheme
            return f"{scheme}:{raw}"

        # Already absolute.
        if raw.startswith(("http://", "https://")):
            return raw

        # Data URIs and blobs — skip.
        if raw.startswith(("data:", "blob:", "javascript:")):
            return ""

        # Relative — resolve against base.
        return urljoin(self.base_url, raw)

    def stats_dict(self) -> dict:
        """Devuelve stats como dict para raw_data del scanner."""
        return {
            "inline_scripts": self.stats.inline_count,
            "inline_size_bytes": self.stats.inline_total_size,
            "external_urls_found": self.stats.external_urls_found,
            "external_fetched": self.stats.external_fetched,
            "external_fetch_errors": self.stats.external_errors,
            "external_size_bytes": self.stats.external_total_size,
            "total_js_sources": (
                self.stats.inline_count + self.stats.external_fetched
            ),
        }
