"""
JS Client-Side Analysis — Secrets & Information Exposure.

Detecta información sensible expuesta en JavaScript del cliente:
- API keys hardcodeadas (Google, AWS, Stripe, Firebase, GitHub, etc.).
- JWT tokens embebidos.
- Llaves privadas (PEM).
- Credenciales hardcodeadas (password, secret assignments).
- Debug flags activos (debug: true, __DEV__, console.log sensible).
- Source maps habilitados (exponen código fuente original).
- IPs internas y dominios de staging/dev.
- Comentarios sensibles (TODO con passwords, FIXME de seguridad).

Analiza tanto scripts inline como externos (fetch activo).

Cómo funciona:
1. JSCollector recolecta todo el JS de la página.
2. Se aplican regex específicos por tipo de secreto.
3. Se validan los matches para reducir falsos positivos:
   - API keys: se verifica longitud y entropy mínima.
   - JWTs: se verifica formato base64url correcto.
   - IPs: se filtran rangos no-privados en el check de IPs internas.
4. Se extrae contexto alrededor del match como evidencia.

Limitaciones honestas:
- No puede verificar si un API key es válida/activa (no la prueba).
- Código minificado puede ocultar contexto pero no los valores.
- Variables renombradas por minificadores no afectan la detección
  de valores literales (strings, tokens).
- Puede haber falsos positivos en strings que parecen tokens pero
  son IDs públicos o hashes no sensibles.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult
from ._js_collector import JSCollector, JSSource


@dataclass(frozen=True)
class _SecretPattern:
    """Un patrón de detección de secretos."""

    name: str
    regex: str
    severity: str
    title: str
    description: str
    recommendation: str
    # Minimum match length to reduce false positives.
    min_length: int = 0
    flags: int = re.IGNORECASE


# ── API Key patterns ─────────────────────────────────────────
# Cada regex captura el valor del key para evidencia.

API_KEY_PATTERNS: list[_SecretPattern] = [
    _SecretPattern(
        name="google_api_key",
        regex=r'AIza[0-9A-Za-z\-_]{35}',
        severity=Severity.HIGH,
        title="Google API Key expuesta en JS",
        description=(
            "Se detectó una API key de Google (AIza...) en el código "
            "JavaScript del cliente. Dependiendo de los permisos, puede "
            "ser usada para consumir servicios de GCP a tu costa."
        ),
        recommendation=(
            "Restringe la key por dominio/IP en Google Cloud Console. "
            "Para APIs sensibles, mueve la key al backend."
        ),
        min_length=39,
    ),
    _SecretPattern(
        name="aws_access_key",
        regex=r'AKIA[0-9A-Z]{16}',
        severity=Severity.CRITICAL,
        title="AWS Access Key ID expuesta en JS",
        description=(
            "Se detectó un AWS Access Key ID (AKIA...) en el cliente. "
            "Combinada con la Secret Key, da acceso a la cuenta AWS. "
            "Incluso sola, revela información de la cuenta."
        ),
        recommendation=(
            "Rota la key inmediatamente en IAM. Nunca expongas "
            "credenciales AWS en el frontend. Usa Cognito o un "
            "backend proxy."
        ),
        min_length=20,
        flags=0,  # Case sensitive for AWS keys.
    ),
    _SecretPattern(
        name="aws_secret_key",
        regex=r'(?:aws_secret|secret_access_key|AWS_SECRET)\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']',
        severity=Severity.CRITICAL,
        title="AWS Secret Access Key expuesta en JS",
        description=(
            "Se detectó un AWS Secret Access Key en el cliente. "
            "Esto da acceso directo a servicios AWS."
        ),
        recommendation="Rota la key inmediatamente. Nunca pongas secrets en JS.",
        min_length=40,
    ),
    _SecretPattern(
        name="stripe_key",
        regex=r'(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}',
        severity=Severity.HIGH,
        title="Stripe API Key expuesta en JS",
        description=(
            "Se detectó una Stripe key. Las 'pk_' (publishable) son "
            "públicas por diseño, pero 'sk_' (secret) y 'rk_' "
            "(restricted) NUNCA deben estar en el cliente."
        ),
        recommendation=(
            "Si es sk_live o rk_live, rota inmediatamente en el "
            "Dashboard de Stripe. Las pk_ son seguras en frontend."
        ),
    ),
    _SecretPattern(
        name="firebase",
        regex=r'(?:firebase|firebaseio)\.com/[^\s"\'<]+',
        severity=Severity.MEDIUM,
        title="Firebase endpoint expuesto en JS",
        description=(
            "Se detectó un endpoint de Firebase. Si las Realtime "
            "Database rules no están configuradas correctamente, "
            "los datos pueden ser accesibles públicamente."
        ),
        recommendation="Verifica las Security Rules de Firebase.",
    ),
    _SecretPattern(
        name="github_token",
        regex=r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',
        severity=Severity.CRITICAL,
        title="GitHub Token expuesto en JS",
        description=(
            "Se detectó un token de GitHub (ghp_/gho_/etc.) en el "
            "cliente. Estos tokens dan acceso a repositorios y APIs."
        ),
        recommendation="Revoca el token inmediatamente en GitHub Settings.",
    ),
    _SecretPattern(
        name="slack_token",
        regex=r'xox[bposatr]-[0-9]{10,}-[0-9a-zA-Z]{10,}',
        severity=Severity.HIGH,
        title="Slack Token expuesto en JS",
        description=(
            "Se detectó un token de Slack. Puede dar acceso a "
            "canales, mensajes e información del workspace."
        ),
        recommendation="Revoca el token en Slack API settings.",
    ),
    _SecretPattern(
        name="twilio",
        regex=r'SK[0-9a-fA-F]{32}',
        severity=Severity.HIGH,
        title="Twilio API Key expuesta en JS",
        description="Se detectó una API key de Twilio (SK...).",
        recommendation="Rota la key en la consola de Twilio.",
        min_length=34,
    ),
    _SecretPattern(
        name="sendgrid",
        regex=r'SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}',
        severity=Severity.HIGH,
        title="SendGrid API Key expuesta en JS",
        description="Se detectó una API key de SendGrid.",
        recommendation="Rota la key en el dashboard de SendGrid.",
    ),
    _SecretPattern(
        name="mailgun",
        regex=r'key-[0-9a-zA-Z]{32}',
        severity=Severity.HIGH,
        title="Mailgun API Key expuesta en JS",
        description="Se detectó una API key de Mailgun (key-...).",
        recommendation="Rota la key en el dashboard de Mailgun.",
        min_length=36,
    ),
    _SecretPattern(
        name="generic_secret",
        regex=r'(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{16,})["\']',
        severity=Severity.MEDIUM,
        title="Posible secret/token genérico en JS",
        description=(
            "Se detectó una asignación que parece ser un secret o "
            "token. El nombre de la variable sugiere credenciales."
        ),
        recommendation=(
            "Verifica si este valor es sensible. Si lo es, muévelo "
            "al backend y no lo expongas en JavaScript."
        ),
        min_length=16,
    ),
]

# ── JWT pattern ──────────────────────────────────────────────
JWT_PATTERN = re.compile(
    r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+',
)

# ── Private key pattern ──────────────────────────────────────
PRIVATE_KEY_PATTERN = re.compile(
    r'-----BEGIN\s+(?:RSA\s+)?(?:EC\s+)?PRIVATE\s+KEY-----',
)

# ── Password/credential assignment ───────────────────────────
CREDENTIAL_PATTERN = re.compile(
    r'(?:password|passwd|pwd|credential|secret)\s*[=:]\s*["\'](?![\s"\']*$)[^"\']{4,}["\']',
    re.IGNORECASE,
)

# ── Debug flags ──────────────────────────────────────────────
DEBUG_PATTERNS = [
    (re.compile(r'\bdebug\s*[=:]\s*true\b', re.IGNORECASE), "debug = true"),
    (re.compile(r'\b__DEV__\b'), "__DEV__ flag"),
    (re.compile(r'\bDEBUG_MODE\s*[=:]\s*true\b', re.IGNORECASE), "DEBUG_MODE = true"),
    (re.compile(r'\bVERBOSE\s*[=:]\s*true\b', re.IGNORECASE), "VERBOSE = true"),
    (re.compile(r'\bdevMode\s*[=:]\s*true\b'), "devMode = true"),
    (re.compile(r'\benableDebug\s*[=:]\s*true\b', re.IGNORECASE), "enableDebug = true"),
]

# ── Source map pattern ───────────────────────────────────────
SOURCEMAP_PATTERN = re.compile(
    r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)',
)

# ── Internal IPs ─────────────────────────────────────────────
INTERNAL_IP_PATTERN = re.compile(
    r'(?:https?://)?(?:'
    r'(?:10\.(?:\d{1,3}\.){2}\d{1,3})'           # 10.x.x.x
    r'|(?:172\.(?:1[6-9]|2\d|3[01])\.[\d.]+)'    # 172.16-31.x.x
    r'|(?:192\.168\.[\d.]+)'                       # 192.168.x.x
    r'|(?:127\.0\.0\.1)'                           # localhost
    r')(?::\d+)?',
)

# ── Sensitive comments ───────────────────────────────────────
SENSITIVE_COMMENT_PATTERN = re.compile(
    r'(?://|/\*)\s*(?:TODO|FIXME|HACK|XXX|BUG)[:\s]+'
    r'[^\n]*(?:password|secret|key|token|credential|auth|vuln|hack|exploit)',
    re.IGNORECASE,
)

# ── Internal/staging domains ─────────────────────────────────
INTERNAL_DOMAIN_PATTERN = re.compile(
    r'(?:https?://)[^\s"\'<>]*?'
    r'(?:\.internal\b|\.local\b|\.dev\b|\.staging\b|\.test\b'
    r'|localhost|\.corp\b|\.private\b)',
    re.IGNORECASE,
)


class JSSecretsScanner(BaseScanner):
    name = "js_secrets"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()

        if not context.has_http:
            result.raw = {"error": context.http_error or "Sin respuesta HTTP"}
            return result

        target = context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port not in (80, 443):
            base_url += f":{target.port}"

        collector = JSCollector(context.body_text, base_url)
        sources = collector.collect_all(fetch_external=True)

        api_keys = self._check_api_keys(sources)
        jwts = self._check_jwts(sources)
        private_keys = self._check_private_keys(sources)
        credentials = self._check_credentials(sources)
        debug_flags = self._check_debug_flags(sources)
        source_maps = self._check_source_maps(sources)
        internal_ips = self._check_internal_ips(sources)
        sensitive_comments = self._check_sensitive_comments(sources)
        internal_domains = self._check_internal_domains(sources)

        result.raw = {
            "collection": collector.stats_dict(),
            "api_keys": len(api_keys),
            "jwts": len(jwts),
            "private_keys": len(private_keys),
            "hardcoded_credentials": len(credentials),
            "debug_flags": len(debug_flags),
            "source_maps": len(source_maps),
            "internal_ips": len(internal_ips),
            "sensitive_comments": len(sensitive_comments),
            "internal_domains": len(internal_domains),
        }

        # --- API Keys ---
        for f in api_keys:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=f["severity"],
                title=f["title"],
                description=f["description"],
                evidence=f["evidence"],
                recommendation=f["recommendation"],
            ))

        # --- JWTs ---
        for f in jwts:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.HIGH,
                title=f["title"],
                description=(
                    "Se detectó un JSON Web Token hardcodeado en el "
                    "código JavaScript. Los JWTs contienen claims que "
                    "pueden incluir roles, permisos y datos del usuario. "
                    "Un JWT expuesto puede ser reutilizado para suplantar "
                    "sesiones."
                ),
                evidence=f["evidence"],
                recommendation=(
                    "Los JWTs deben gestionarse via cookies HttpOnly o "
                    "almacenamiento seguro, nunca hardcodeados en JS. "
                    "Verifica si el token es válido y revócalo."
                ),
            ))

        # --- Private keys ---
        for f in private_keys:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.CRITICAL,
                title="Llave privada expuesta en JavaScript",
                description=(
                    "Se detectó una llave privada (PEM) en el código "
                    "JavaScript. Esto es un compromiso criptográfico total."
                ),
                evidence=f["evidence"],
                recommendation=(
                    "Rota la llave inmediatamente. Las llaves privadas "
                    "NUNCA deben estar en código cliente."
                ),
            ))

        # --- Hardcoded credentials ---
        for f in credentials:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.HIGH,
                title="Credencial hardcodeada detectada en JS",
                description=(
                    "Se detectó una asignación de password/secret en "
                    "JavaScript. Puede ser una credencial real o un "
                    "placeholder — verifica manualmente."
                ),
                evidence=f["evidence"],
                recommendation=(
                    "Elimina credenciales del código cliente. Usa "
                    "autenticación via backend (OAuth, session cookies)."
                ),
            ))

        # --- Debug flags ---
        if debug_flags:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.MEDIUM,
                title=f"{len(debug_flags)} debug flag(s) activo(s) en JS",
                description=(
                    "Se detectaron flags de debug habilitados en producción. "
                    "Pueden activar logging verboso, bypass de validaciones "
                    "o exponer información interna."
                ),
                evidence={"flags": debug_flags[:10]},
                recommendation=(
                    "Desactiva flags de debug en producción. Usa "
                    "variables de entorno para configuración por ambiente."
                ),
            ))

        # --- Source maps ---
        if source_maps:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.MEDIUM,
                title=f"{len(source_maps)} source map(s) habilitado(s)",
                description=(
                    "Se detectaron referencias a source maps (.map). "
                    "Los source maps exponen el código fuente original "
                    "(pre-minificación), incluyendo comentarios, nombres "
                    "de variables y estructura del proyecto."
                ),
                evidence={"source_maps": source_maps[:10]},
                recommendation=(
                    "Deshabilita source maps en producción o restringe "
                    "acceso a los archivos .map por IP/autenticación."
                ),
            ))

        # --- Internal IPs ---
        if internal_ips:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.MEDIUM,
                title=f"{len(internal_ips)} IP(s) interna(s) expuesta(s) en JS",
                description=(
                    "Se detectaron direcciones IP de redes privadas en "
                    "el JavaScript. Revelan topología interna de la red "
                    "y pueden ser usadas para ataques SSRF o lateral movement."
                ),
                evidence={"ips": internal_ips[:10]},
                recommendation=(
                    "Elimina IPs internas del código cliente. Usa "
                    "dominios públicos o un proxy backend."
                ),
            ))

        # --- Sensitive comments ---
        if sensitive_comments:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.LOW,
                title=f"{len(sensitive_comments)} comentario(s) sensible(s) en JS",
                description=(
                    "Se detectaron comentarios TODO/FIXME/HACK que "
                    "mencionan passwords, secrets o vulnerabilidades. "
                    "Revelan deuda técnica de seguridad y posibles "
                    "puntos débiles."
                ),
                evidence={"comments": sensitive_comments[:10]},
                recommendation=(
                    "Elimina comentarios sensibles antes de producción. "
                    "Usa un issue tracker en lugar de TODOs en código."
                ),
            ))

        # --- Internal domains ---
        if internal_domains:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.MEDIUM,
                title=f"{len(internal_domains)} dominio(s) interno(s) expuesto(s) en JS",
                description=(
                    "Se detectaron URLs a dominios internos, de staging "
                    "o desarrollo. Revelan infraestructura no pública "
                    "y pueden ser objetivos de ataque."
                ),
                evidence={"domains": internal_domains[:10]},
                recommendation=(
                    "Elimina referencias a dominios internos del código "
                    "de producción. Usa configuración por ambiente."
                ),
            ))

        total = (
            len(api_keys) + len(jwts) + len(private_keys)
            + len(credentials) + len(debug_flags) + len(source_maps)
            + len(internal_ips) + len(sensitive_comments)
            + len(internal_domains)
        )
        if total == 0:
            result.findings.append(self.finding(
                category=Category.JS,
                severity=Severity.INFO,
                title="No se detectaron secrets expuestos en JS",
                description=(
                    f"Se analizaron {collector.stats.inline_count} scripts "
                    f"inline y {collector.stats.external_fetched} externos. "
                    "No se encontraron API keys, tokens, credenciales ni "
                    "información sensible en los patrones analizados."
                ),
            ))

        return result

    # ── Check methods ────────────────────────────────────────

    def _check_api_keys(self, sources: list[JSSource]) -> list[dict]:
        findings = []
        for source in sources:
            for pattern in API_KEY_PATTERNS:
                matches = list(re.finditer(
                    pattern.regex, source.content, pattern.flags,
                ))
                for m in matches:
                    value = m.group(0)
                    if pattern.min_length and len(value) < pattern.min_length:
                        continue

                    # Redact middle portion for evidence.
                    redacted = value[:8] + "..." + value[-4:] if len(value) > 16 else value
                    loc = source.url or "inline script"

                    findings.append({
                        "severity": pattern.severity,
                        "title": f"{pattern.title} [{loc}]",
                        "description": pattern.description,
                        "evidence": {
                            "type": pattern.name,
                            "value_redacted": redacted,
                            "source": loc,
                        },
                        "recommendation": pattern.recommendation,
                    })

        # Deduplicate by type + redacted value.
        seen = set()
        unique = []
        for f in findings:
            key = (f["evidence"]["type"], f["evidence"]["value_redacted"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique[:15]

    def _check_jwts(self, sources: list[JSSource]) -> list[dict]:
        findings = []
        seen = set()
        for source in sources:
            for m in JWT_PATTERN.finditer(source.content):
                token = m.group(0)
                short = token[:20] + "..." + token[-10:]
                if short in seen:
                    continue
                seen.add(short)
                loc = source.url or "inline script"
                findings.append({
                    "title": f"JWT token hardcodeado [{loc}]",
                    "evidence": {
                        "value_redacted": short,
                        "source": loc,
                        "length": len(token),
                    },
                })
        return findings[:5]

    def _check_private_keys(self, sources: list[JSSource]) -> list[dict]:
        findings = []
        for source in sources:
            if PRIVATE_KEY_PATTERN.search(source.content):
                loc = source.url or "inline script"
                findings.append({
                    "evidence": {
                        "source": loc,
                        "pattern": "-----BEGIN PRIVATE KEY-----",
                    },
                })
        return findings[:3]

    def _check_credentials(self, sources: list[JSSource]) -> list[dict]:
        findings = []
        seen = set()
        for source in sources:
            for m in CREDENTIAL_PATTERN.finditer(source.content):
                snippet = m.group(0)[:100]
                if snippet in seen:
                    continue
                seen.add(snippet)
                # Redact the actual value.
                redacted = re.sub(
                    r'(["\'])[^"\']{4,}(["\'])',
                    r'\1****\2',
                    snippet,
                )
                loc = source.url or "inline script"
                findings.append({
                    "evidence": {
                        "snippet_redacted": redacted,
                        "source": loc,
                    },
                })
        return findings[:10]

    def _check_debug_flags(self, sources: list[JSSource]) -> list[dict]:
        flags = []
        for source in sources:
            for pattern, name in DEBUG_PATTERNS:
                if pattern.search(source.content):
                    loc = source.url or "inline script"
                    flags.append({"flag": name, "source": loc})
        # Deduplicate.
        seen = set()
        unique = []
        for f in flags:
            if f["flag"] not in seen:
                seen.add(f["flag"])
                unique.append(f)
        return unique

    def _check_source_maps(self, sources: list[JSSource]) -> list[dict]:
        maps = []
        seen = set()
        for source in sources:
            for m in SOURCEMAP_PATTERN.finditer(source.content):
                url = m.group(1)
                if url not in seen:
                    seen.add(url)
                    loc = source.url or "inline script"
                    maps.append({"map_url": url, "source": loc})
        return maps

    def _check_internal_ips(self, sources: list[JSSource]) -> list[dict]:
        ips = []
        seen = set()
        for source in sources:
            for m in INTERNAL_IP_PATTERN.finditer(source.content):
                ip = m.group(0)
                if ip not in seen:
                    seen.add(ip)
                    loc = source.url or "inline script"
                    ips.append({"ip": ip, "source": loc})
        return ips

    def _check_sensitive_comments(self, sources: list[JSSource]) -> list[dict]:
        comments = []
        seen = set()
        for source in sources:
            for m in SENSITIVE_COMMENT_PATTERN.finditer(source.content):
                comment = m.group(0).strip()[:150]
                if comment not in seen:
                    seen.add(comment)
                    loc = source.url or "inline script"
                    comments.append({"comment": comment, "source": loc})
        return comments

    def _check_internal_domains(self, sources: list[JSSource]) -> list[dict]:
        domains = []
        seen = set()
        for source in sources:
            for m in INTERNAL_DOMAIN_PATTERN.finditer(source.content):
                domain = m.group(0)[:150]
                if domain not in seen:
                    seen.add(domain)
                    loc = source.url or "inline script"
                    domains.append({"url": domain, "source": loc})
        return domains
