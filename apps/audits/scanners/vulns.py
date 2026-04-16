"""
Vulnerabilidades básicas detectables desde el HTML.

Comprueba:
- Formularios POST sin nada que parezca un token CSRF.
- Mixed content: recursos HTTP cargados desde una página HTTPS.
- Formularios que envían a action="http://..." desde HTTPS.

No intentamos inyectar XSS reflejado real aquí: hacerlo contra un
objetivo del cliente roza lo legalmente gris y requiere consentimiento
explícito. Lo dejamos como nota para una fase avanzada bajo opt-in.
"""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

CSRF_TOKEN_HINTS = ("csrf", "token", "authenticity", "_token", "nonce")


class _FormParser(HTMLParser):
    """Parser minimalista para extraer formularios, inputs, iframes e imgs."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.iframes_src: list[str] = []
        self.imgs_src: list[str] = []
        self.scripts_src: list[str] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_d = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current_form = {
                "method": attrs_d.get("method", "get").lower(),
                "action": attrs_d.get("action", ""),
                "inputs": [],
            }
            self.forms.append(self._current_form)
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "type": attrs_d.get("type", "text").lower(),
                    "name": attrs_d.get("name", ""),
                }
            )
        elif tag == "iframe":
            src = attrs_d.get("src", "")
            if src:
                self.iframes_src.append(src)
        elif tag == "img":
            src = attrs_d.get("src", "")
            if src:
                self.imgs_src.append(src)
        elif tag == "script":
            src = attrs_d.get("src", "")
            if src:
                self.scripts_src.append(src)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None


class VulnsScanner(BaseScanner):
    name = "vulns"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        if not context.has_http:
            result.raw = {"error": context.http_error or "Sin respuesta HTTP"}
            return result

        html = context.body_text
        if not html:
            result.raw = {"error": "Respuesta sin cuerpo HTML"}
            return result

        parser = _FormParser()
        try:
            parser.feed(html)
        except Exception as exc:
            result.raw = {"error": f"Error parseando HTML: {exc}"}
            return result

        result.raw = {
            "forms_found": len(parser.forms),
            "iframes_found": len(parser.iframes_src),
            "scripts_found": len(parser.scripts_src),
        }

        base_url = str(context.http_response.url)  # URL final tras redirects
        is_https = base_url.startswith("https://")

        # --- Formularios POST sin token CSRF heurístico ---
        for idx, form in enumerate(parser.forms):
            if form["method"] != "post":
                continue
            names = [i["name"].lower() for i in form["inputs"] if i["type"] == "hidden"]
            has_token = any(
                any(hint in name for hint in CSRF_TOKEN_HINTS) for name in names
            )
            if not has_token:
                result.findings.append(
                    self.finding(
                        category=Category.VULNS,
                        severity=Severity.MEDIUM,
                        title="Formulario POST sin token CSRF aparente",
                        description=(
                            "El formulario envía datos por POST y no contiene "
                            "ningún input oculto que parezca un token CSRF."
                        ),
                        evidence={
                            "form_index": idx,
                            "action": form["action"],
                            "hidden_inputs": names,
                        },
                        recommendation=(
                            "Incluye un token CSRF aleatorio por sesión en cada "
                            "formulario POST y valídalo en el servidor."
                        ),
                        reference_url="https://owasp.org/www-community/attacks/csrf",
                    )
                )

            # action http:// desde página https://
            action_abs = urljoin(base_url, form["action"])
            if is_https and action_abs.startswith("http://"):
                result.findings.append(
                    self.finding(
                        category=Category.VULNS,
                        severity=Severity.HIGH,
                        title="Formulario que envía a HTTP desde página HTTPS",
                        description=(
                            "Las credenciales o datos enviados pueden interceptarse."
                        ),
                        evidence={"action": action_abs},
                        recommendation="Usa HTTPS en el atributo action del form.",
                    )
                )

        # --- Mixed content ---
        if is_https:
            insecure_assets = []
            for src in parser.scripts_src + parser.iframes_src + parser.imgs_src:
                if src.startswith("http://"):
                    insecure_assets.append(src)
            if insecure_assets:
                result.findings.append(
                    self.finding(
                        category=Category.VULNS,
                        severity=Severity.MEDIUM,
                        title="Contenido mixto (mixed content)",
                        description=(
                            f"Se encontraron {len(insecure_assets)} recursos "
                            "cargados por HTTP en una página servida por HTTPS."
                        ),
                        evidence={"assets": insecure_assets[:20]},
                        recommendation=(
                            "Migra todos los recursos estáticos a HTTPS o usa URLs "
                            "protocolo-relativas."
                        ),
                    )
                )

        return result
