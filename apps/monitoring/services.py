"""
Monitoring Check Engine — motor de comprobación modular.

Flujo por ejecución (run_check):
  1. Validación anti-SSRF de la URL
  2. HTTP probe: uptime, response time, security headers, content hash,
     todos los headers raw, body snippet (para análisis posterior)
  3. SSL probe: expiración, emisor, fingerprint
  4. Tech detection: stack tecnológico desde headers + cookies + HTML
  5. WAF detection: WAF/CDN desde response headers
  6. Sensitive path discovery: paths sensibles con status != 404
  7. Security score: puntuación 0-100 ponderada
  8. Crear MonitorCheck con todos los datos
  9. Detectar cambios vs check anterior → crear MonitorChange records
 10. Actualizar campos cacheados en MonitorTarget
 11. Enviar alertas email para cambios CRITICAL/HIGH

Seguridad:
  - Anti-SSRF via resolve_and_validate (audits).
  - Timeout 10s para el probe principal, 3s para sensitive paths.
  - Solo IPs públicas (filtrado en resolve_and_validate).
"""
from __future__ import annotations

import datetime
import hashlib
import logging
import socket
import ssl

from typing import Optional
from urllib.parse import urlparse

import requests
from django.utils import timezone

from apps.audits.validators import resolve_and_validate
from django.core.exceptions import ValidationError

from .checks import (
    calculate_security_score,
    check_sensitive_paths,
    check_subdomains,
    detect_technologies,
    detect_waf,
    process_screenshot,
)

logger = logging.getLogger(__name__)

HTTP_TIMEOUT     = 10
PATH_TIMEOUT     = 3
UA               = "AttackFlow-Monitor/1.0"
SSL_WARN_DAYS    = 30
SSL_CRITICAL_DAYS = 7
SLOW_RESPONSE_MS = 3000
SCORE_DROP_THRESHOLD  = 10   # Reportar si el score cae >= 10 puntos
DEEP_CHECK_INTERVAL_H = 6    # Horas entre deep checks (subdomains + sensitive paths)

# Headers de seguridad que se monitorizan para detectar cambios.
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Access-Control-Allow-Origin",
    "X-XSS-Protection",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]


# ── Public API ──────────────────────────────────────────────────────────────

def run_check(target) -> "MonitorCheck":
    """
    Ejecuta una comprobación completa para un MonitorTarget.

    Retorna el MonitorCheck creado. Los MonitorChange se crean
    automáticamente si se detectan diferencias con el check anterior.
    """
    from .models import MonitorCheck, CheckStatus

    # 1. Validación anti-SSRF
    try:
        scan_target = resolve_and_validate(target.url)
    except ValidationError as exc:
        check = MonitorCheck.objects.create(
            target=target,
            status=CheckStatus.ERROR,
            error_message=f"URL inválida o bloqueada: {exc}",
        )
        _update_target_status(target, check)
        return check

    # 2. HTTP probe
    probe = _probe_http(target.url)

    # 3. SSL probe
    ssl_data: dict = {}
    if scan_target.scheme == "https":
        ssl_data = _probe_ssl(scan_target.hostname, scan_target.port or 443)

    # 4. Determinar status
    if probe.get("error"):
        from .models import CheckStatus
        status = (
            CheckStatus.DOWN
            if "connection" in probe["error"].lower()
            else CheckStatus.ERROR
        )
    elif probe.get("status_code", 0) >= 500:
        from .models import CheckStatus
        status = CheckStatus.DOWN
    elif probe.get("status_code", 0) > 0:
        from .models import CheckStatus
        status = CheckStatus.UP
    else:
        from .models import CheckStatus
        status = CheckStatus.ERROR

    raw_headers   = probe.get("raw_headers", {})
    body_snippet  = probe.get("body_snippet", "")
    cookies       = probe.get("cookies", {})
    ssl_days      = ssl_data.get("expiry_days")

    # 5. Tech + WAF + sensitive paths
    # En modo live (intervalo ≤ 60s) se omite el escaneo de paths sensibles
    # en cada check para no saturar el servidor. El deep check (cada 6h)
    # siempre los incluye, independientemente del intervalo.
    is_live = getattr(target, "check_interval", 1800) <= 60
    technologies: list[str] = []
    waf_detected: str = ""
    sensitive_paths: list[dict] = []

    if not probe.get("error"):
        technologies = detect_technologies(
            raw_headers=raw_headers,
            body_snippet=body_snippet,
            cookies=cookies,
        )
        waf_detected = detect_waf(raw_headers)

        if target.check_sensitive_paths and not is_live:
            try:
                sensitive_paths = check_sensitive_paths(
                    target.url, timeout=PATH_TIMEOUT
                )
            except Exception:
                logger.exception("Sensitive path scan failed for %s", target.url)

    # 6. Security score
    security_score = calculate_security_score(
        headers_snapshot=probe.get("headers", {}),
        ssl_expiry_days=ssl_days,
        sensitive_paths_found=sensitive_paths,
    )

    # 7. Crear MonitorCheck
    check = MonitorCheck.objects.create(
        target=target,
        status=status,
        http_status_code=probe.get("status_code"),
        response_time_ms=probe.get("response_ms"),
        headers_snapshot=probe.get("headers", {}),
        content_hash=probe.get("content_hash", ""),
        ssl_expiry_days=ssl_days,
        ssl_issuer=(ssl_data.get("issuer") or "")[:256],
        ssl_fingerprint=(ssl_data.get("fingerprint") or "")[:128],
        technologies=technologies,
        waf_detected=waf_detected,
        sensitive_paths_found=sensitive_paths,
        security_score=security_score,
        error_message=probe.get("error", "") or ssl_data.get("error", ""),
    )

    # 8. Detectar cambios vs check anterior
    try:
        prev = (
            MonitorCheck.objects
            .filter(target=target)
            .exclude(pk=check.pk)
            .order_by("-created_at")
            .first()
        )
        if prev:
            _detect_changes(target, prev, check)
    except Exception:
        logger.exception("Change detection failed for target %s", target.pk)

    # 9. Actualizar cache del target
    _update_target_status(target, check)

    # 10. Deep check (subdomains + sensitive paths para live targets) cada 6h
    if _is_deep_check_due(target):
        try:
            _run_deep_check(target, check)
        except Exception:
            logger.exception("Deep check falló para target %s", target.pk)

    return check


# ── Internal probes ─────────────────────────────────────────────────────────

def _probe_http(url: str) -> dict:
    """
    Realiza un GET y retorna métricas + snapshots.

    Keys del dict retornado:
        status_code, response_ms, headers (security headers),
        raw_headers (todos), body_snippet, cookies, content_hash.
        En caso de error: {"error": "mensaje"}.
    """
    try:
        start = timezone.now()
        resp = requests.get(
            url,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": UA},
            allow_redirects=True,
        )
        elapsed_ms = int((timezone.now() - start).total_seconds() * 1000)

        # Solo security headers para el snapshot de cambios
        sec_headers = {}
        for h in SECURITY_HEADERS:
            val = resp.headers.get(h, "")
            if val:
                sec_headers[h] = val

        # Todos los headers para tech/WAF detection
        raw_headers = dict(resp.headers)

        # Cookies
        cookies = {c.name: c.value for c in resp.cookies}

        # Hash de los primeros 50KB
        body_snippet = resp.text[:51200]
        content_hash = hashlib.md5(
            body_snippet.encode(errors="replace"),
            usedforsecurity=False,
        ).hexdigest()

        return {
            "status_code":  resp.status_code,
            "response_ms":  elapsed_ms,
            "headers":      sec_headers,
            "raw_headers":  raw_headers,
            "body_snippet": body_snippet,
            "cookies":      cookies,
            "content_hash": content_hash,
        }
    except requests.exceptions.ConnectionError as exc:
        return {"error": f"Connection error: {exc}"}
    except requests.exceptions.Timeout:
        return {"error": "Request timed out"}
    except requests.exceptions.RequestException as exc:
        return {"error": f"Request error: {exc}"}


def _probe_ssl(hostname: str, port: int = 443) -> dict:
    """Obtiene info del certificado SSL: expiración, emisor, fingerprint."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                bin_cert = ssock.getpeercert(binary_form=True)

        not_after = cert.get("notAfter", "")
        expiry_days: Optional[int] = None
        if not_after:
            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            exp = exp.replace(tzinfo=datetime.timezone.utc)
            expiry_days = (exp - datetime.datetime.now(datetime.timezone.utc)).days

        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        issuer = issuer_dict.get("organizationName", "") or issuer_dict.get("commonName", "")

        fingerprint = hashlib.sha256(bin_cert).hexdigest()[:32] if bin_cert else ""

        return {
            "expiry_days": expiry_days,
            "issuer":      issuer,
            "fingerprint": fingerprint,
        }
    except ssl.SSLError as exc:
        return {"error": f"SSL error: {exc}"}
    except (socket.timeout, socket.gaierror, OSError) as exc:
        return {"error": f"Connection error: {exc}"}
    except Exception as exc:
        logger.debug("SSL probe error for %s: %s", hostname, exc)
        return {"error": f"Unexpected SSL error: {exc}"}


# ── Change detection ────────────────────────────────────────────────────────

def _detect_changes(target, prev: "MonitorCheck", curr: "MonitorCheck") -> None:
    """
    Compara dos MonitorCheck y crea MonitorChange records por cada
    diferencia relevante detectada.
    """
    from .models import MonitorChange, ChangeType, ChangeSeverity

    changes: list[dict] = []

    # ── 1. Status transition ────────────────────────────────────────────
    if prev.status != curr.status:
        if curr.status == "down":
            changes.append(dict(
                change_type=ChangeType.STATUS_DOWN,
                severity=ChangeSeverity.CRITICAL,
                description="Target pasó a OFFLINE",
                old_value=prev.status,
                new_value=curr.status,
            ))
        elif curr.status == "up" and prev.status in ("down", "error"):
            changes.append(dict(
                change_type=ChangeType.STATUS_UP,
                severity=ChangeSeverity.INFO,
                description="Target volvió a ONLINE",
                old_value=prev.status,
                new_value=curr.status,
            ))

    # ── 2. HTTP status code ─────────────────────────────────────────────
    if (prev.http_status_code and curr.http_status_code
            and prev.http_status_code != curr.http_status_code):
        sev = ChangeSeverity.HIGH if curr.http_status_code >= 400 else ChangeSeverity.MEDIUM
        changes.append(dict(
            change_type=ChangeType.HTTP_STATUS,
            severity=sev,
            description=f"HTTP status: {prev.http_status_code} → {curr.http_status_code}",
            old_value=str(prev.http_status_code),
            new_value=str(curr.http_status_code),
        ))

    # ── 3. Security headers diff ────────────────────────────────────────
    old_hdrs = prev.headers_snapshot or {}
    new_hdrs = curr.headers_snapshot or {}
    for hdr in set(old_hdrs) | set(new_hdrs):
        old_val = old_hdrs.get(hdr, "")
        new_val = new_hdrs.get(hdr, "")
        if old_val == new_val:
            continue
        if old_val and not new_val:
            changes.append(dict(
                change_type=ChangeType.HEADER_REMOVED,
                severity=ChangeSeverity.HIGH,
                description=f"Security header eliminado: {hdr}",
                old_value=old_val[:300],
                new_value="",
            ))
        elif not old_val and new_val:
            changes.append(dict(
                change_type=ChangeType.HEADER_ADDED,
                severity=ChangeSeverity.LOW,
                description=f"Security header añadido: {hdr}",
                old_value="",
                new_value=new_val[:300],
            ))
        else:
            changes.append(dict(
                change_type=ChangeType.HEADER_CHANGED,
                severity=ChangeSeverity.MEDIUM,
                description=f"Security header modificado: {hdr}",
                old_value=old_val[:300],
                new_value=new_val[:300],
            ))

    # ── 4. SSL expiry warnings ──────────────────────────────────────────
    if curr.ssl_expiry_days is not None:
        if curr.ssl_expiry_days <= SSL_CRITICAL_DAYS:
            changes.append(dict(
                change_type=ChangeType.SSL_EXPIRY_WARN,
                severity=ChangeSeverity.CRITICAL,
                description=f"Certificado SSL expira en {curr.ssl_expiry_days} días",
                old_value="",
                new_value=str(curr.ssl_expiry_days),
            ))
        elif curr.ssl_expiry_days <= SSL_WARN_DAYS:
            if not prev.ssl_expiry_days or prev.ssl_expiry_days > SSL_WARN_DAYS:
                changes.append(dict(
                    change_type=ChangeType.SSL_EXPIRY_WARN,
                    severity=ChangeSeverity.HIGH,
                    description=f"Certificado SSL expira en {curr.ssl_expiry_days} días",
                    old_value=str(prev.ssl_expiry_days or ""),
                    new_value=str(curr.ssl_expiry_days),
                ))

    if (prev.ssl_fingerprint and curr.ssl_fingerprint
            and prev.ssl_fingerprint != curr.ssl_fingerprint):
        changes.append(dict(
            change_type=ChangeType.SSL_EXPIRY_CHG,
            severity=ChangeSeverity.MEDIUM,
            description="Certificado SSL reemplazado o renovado",
            old_value=prev.ssl_fingerprint,
            new_value=curr.ssl_fingerprint,
        ))

    # ── 5. Content changed ──────────────────────────────────────────────
    if (prev.content_hash and curr.content_hash
            and prev.content_hash != curr.content_hash
            and curr.status == "up"):
        changes.append(dict(
            change_type=ChangeType.CONTENT_CHANGED,
            severity=ChangeSeverity.LOW,
            description="Contenido de la página ha cambiado",
            old_value=prev.content_hash,
            new_value=curr.content_hash,
        ))

    # ── 6. Response time degradation ────────────────────────────────────
    if (prev.response_time_ms and curr.response_time_ms
            and curr.response_time_ms > SLOW_RESPONSE_MS
            and curr.response_time_ms > prev.response_time_ms * 2):
        changes.append(dict(
            change_type=ChangeType.RESPONSE_SLOW,
            severity=ChangeSeverity.LOW,
            description=f"Respuesta degradada: {prev.response_time_ms}ms → {curr.response_time_ms}ms",
            old_value=str(prev.response_time_ms),
            new_value=str(curr.response_time_ms),
        ))

    # ── 7. Technology changes ───────────────────────────────────────────
    prev_techs = set(prev.technologies or [])
    curr_techs = set(curr.technologies or [])

    for tech in curr_techs - prev_techs:
        changes.append(dict(
            change_type=ChangeType.TECH_ADDED,
            severity=ChangeSeverity.MEDIUM,
            description=f"Tecnología detectada: {tech}",
            old_value="",
            new_value=tech,
        ))
    for tech in prev_techs - curr_techs:
        changes.append(dict(
            change_type=ChangeType.TECH_REMOVED,
            severity=ChangeSeverity.LOW,
            description=f"Tecnología ya no detectada: {tech}",
            old_value=tech,
            new_value="",
        ))

    # ── 8. WAF changes ──────────────────────────────────────────────────
    if not prev.waf_detected and curr.waf_detected:
        changes.append(dict(
            change_type=ChangeType.WAF_APPEARED,
            severity=ChangeSeverity.INFO,
            description=f"WAF/CDN detectado: {curr.waf_detected}",
            old_value="",
            new_value=curr.waf_detected,
        ))
    elif prev.waf_detected and not curr.waf_detected:
        changes.append(dict(
            change_type=ChangeType.WAF_GONE,
            severity=ChangeSeverity.HIGH,
            description=f"WAF/CDN ya no detectado (era {prev.waf_detected})",
            old_value=prev.waf_detected,
            new_value="",
        ))

    # ── 9. New sensitive paths found ────────────────────────────────────
    prev_paths = {p["path"] for p in (prev.sensitive_paths_found or [])}
    for path_info in (curr.sensitive_paths_found or []):
        if path_info["path"] not in prev_paths:
            sev_map = {
                "critical": ChangeSeverity.CRITICAL,
                "high":     ChangeSeverity.HIGH,
                "medium":   ChangeSeverity.MEDIUM,
                "info":     ChangeSeverity.INFO,
            }
            sev = sev_map.get(path_info.get("severity", "info"), ChangeSeverity.INFO)
            changes.append(dict(
                change_type=ChangeType.SENSITIVE_PATH,
                severity=sev,
                description=f"{path_info['label']} expuesto: {path_info['path']} [{path_info['status_code']}]",
                old_value="",
                new_value=path_info["path"],
            ))

    # ── 10. Security score drop ─────────────────────────────────────────
    if (prev.security_score is not None and curr.security_score is not None
            and (prev.security_score - curr.security_score) >= SCORE_DROP_THRESHOLD):
        drop = prev.security_score - curr.security_score
        changes.append(dict(
            change_type=ChangeType.SCORE_DROP,
            severity=ChangeSeverity.HIGH,
            description=f"Security score bajó {drop} puntos: {prev.security_score} → {curr.security_score}",
            old_value=str(prev.security_score),
            new_value=str(curr.security_score),
        ))

    # ── Persist + alertas ───────────────────────────────────────────────
    created: list = []
    for c in changes:
        created.append(
            MonitorChange.objects.create(target=target, monitor_check=curr, **c)
        )

    if created:
        try:
            _send_alert_email(target, created)
        except Exception:
            logger.warning(
                "No se pudo enviar alerta email para target %s", target.pk,
            )


# ── Status update ───────────────────────────────────────────────────────────

def _update_target_status(target, check: "MonitorCheck") -> None:
    """Actualiza los campos cacheados del target con los datos del último check."""
    from .models import MonitorCheck

    consecutive_failures = (
        0 if check.status == "up"
        else target.consecutive_failures + 1
    )

    # Uptime % sobre los últimos 30 checks
    recent = (
        MonitorCheck.objects
        .filter(target=target)
        .order_by("-created_at")[:30]
    )
    total = recent.count()
    up_count = sum(1 for c in recent if c.status == "up")
    uptime = round(up_count / total * 100, 2) if total else None

    target.current_status       = check.status
    target.last_check_at        = timezone.now()
    target.last_response_ms     = check.response_time_ms
    target.last_http_status     = check.http_status_code
    target.last_ssl_days        = check.ssl_expiry_days
    target.consecutive_failures = consecutive_failures
    target.uptime_pct           = uptime
    target.last_security_score  = check.security_score
    target.last_technologies    = check.technologies or []
    target.last_waf             = check.waf_detected or ""

    target.save(update_fields=[
        "current_status", "last_check_at", "last_response_ms",
        "last_http_status", "last_ssl_days", "consecutive_failures",
        "uptime_pct", "last_security_score", "last_technologies",
        "last_waf", "updated_at",
    ])


# ── Deep check (subdomains + sensitive paths each 6h) ───────────────────────

def _is_deep_check_due(target) -> bool:
    """True si han pasado ≥ DEEP_CHECK_INTERVAL_H desde el último deep check."""
    if not target.last_deep_check_at:
        return True
    threshold = datetime.timedelta(hours=DEEP_CHECK_INTERVAL_H)
    return timezone.now() >= target.last_deep_check_at + threshold


def _run_deep_check(target, check: "MonitorCheck") -> None:
    """
    Ejecuta:
    1. Sensitive path scan (incluso para live targets).
    2. Subdomain discovery.

    Actualiza MonitorSubdomain records y last_deep_check_at.
    También parchea el MonitorCheck actual con los sensitive_paths encontrados.
    """
    logger.info("Deep check para target %s (%s)", target.pk, target.url)

    # 1. Sensitive paths (para live targets que lo omiten en el check normal)
    sensitive_paths: list[dict] = []
    if target.check_sensitive_paths:
        try:
            sensitive_paths = check_sensitive_paths(target.url, timeout=PATH_TIMEOUT)
            if sensitive_paths:
                # Parchar el check actual con los paths encontrados
                check.sensitive_paths_found = sensitive_paths
                check.save(update_fields=["sensitive_paths_found"])
                logger.info(
                    "Deep check: %d sensitive paths encontrados en %s",
                    len(sensitive_paths), target.url,
                )
        except Exception:
            logger.exception("Sensitive path scan (deep) falló para %s", target.url)

    # 2. Subdomain discovery
    subdomain_results: list[dict] = []
    try:
        subdomain_results = check_subdomains(target.url)
        _update_subdomains(target, subdomain_results)
        logger.info(
            "Deep check: %d subdominios encontrados para %s",
            len(subdomain_results), target.url,
        )
    except Exception:
        logger.exception("Subdomain discovery falló para %s", target.url)

    # 3. Screenshot visual
    try:
        _run_screenshot(target, check)
    except Exception:
        logger.exception("Screenshot falló para %s", target.url)

    # 4. Broadcast surface update via WebSocket
    try:
        from .tasks import _broadcast_surface_update
        _broadcast_surface_update(target, subdomain_results, sensitive_paths)
    except Exception:
        pass  # No crítico

    # 5. Actualizar timestamp del deep check
    target.last_deep_check_at = timezone.now()
    target.save(update_fields=["last_deep_check_at", "updated_at"])


def _run_screenshot(target, check: "MonitorCheck") -> None:
    """
    Toma un screenshot del target y lo guarda como MonitorScreenshot.
    Compara con el screenshot anterior para detectar defacements.
    Hace broadcast WebSocket si hay un cambio significativo.
    """
    from .models import MonitorScreenshot

    # Obtener screenshot anterior para diff
    previous_screenshot = (
        MonitorScreenshot.objects
        .filter(monitor_check__target=target)
        .order_by("-created_at")
        .first()
    )
    previous_b64 = previous_screenshot.image_b64 if previous_screenshot else None

    result = process_screenshot(target.url, previous_b64=previous_b64)
    if not result:
        return  # Playwright no disponible o fallo

    screenshot = MonitorScreenshot.objects.create(
        monitor_check=check,
        image_b64=result["image_b64"],
        image_hash=result["image_hash"],
        diff_pct=result["diff_pct"],
        is_defacement_alert=result["is_defacement_alert"],
        width=result["width"],
        height=result["height"],
    )

    logger.info(
        "Screenshot guardado para %s — diff: %.1f%% alert: %s",
        target.url, result["diff_pct"] or 0, result["is_defacement_alert"],
    )

    # Broadcast WebSocket si hay alerta o es el primero
    try:
        from .tasks import _broadcast_screenshot
        _broadcast_screenshot(target, screenshot)
    except Exception:
        pass

    # Crear MonitorChange si es un posible defacement
    if result["is_defacement_alert"]:
        from .models import MonitorChange, ChangeType, ChangeSeverity
        MonitorChange.objects.create(
            target=target,
            monitor_check=check,
            change_type=ChangeType.CONTENT_CHANGED,
            severity=ChangeSeverity.HIGH,
            description=f"Posible DEFACEMENT detectado — {result['diff_pct']:.1f}% de la página cambió visualmente",
            old_value=previous_screenshot.image_hash if previous_screenshot else "",
            new_value=result["image_hash"],
        )


def _update_subdomains(target, results: list[dict]) -> None:
    """
    Sincroniza los resultados del subdomain probe con MonitorSubdomain.

    - Para cada resultado activo: update_or_create → actualiza is_active + last_seen_at.
    - Subdomains que ya no aparecen (pero existían) → is_active=False.
    """
    from .models import MonitorSubdomain

    now = timezone.now()
    seen_hostnames: set[str] = set()

    for r in results:
        hostname = r["hostname"]
        seen_hostnames.add(hostname)

        defaults = {
            "subdomain":        r["subdomain"],
            "ip_address":       r.get("ip_address", ""),
            "is_active":        r["is_active"],
            "http_status_code": r.get("http_status_code"),
            "response_time_ms": r.get("response_time_ms"),
        }
        if r["is_active"]:
            defaults["last_seen_at"] = now

        MonitorSubdomain.objects.update_or_create(
            target=target,
            hostname=hostname,
            defaults=defaults,
        )

    # Marcar como inactivos los que no aparecieron en este scan
    if seen_hostnames:
        (
            MonitorSubdomain.objects
            .filter(target=target, is_active=True)
            .exclude(hostname__in=seen_hostnames)
            .update(is_active=False)
        )


# ── Email alerts ────────────────────────────────────────────────────────────

def _send_alert_email(target, changes: list) -> None:
    """
    Envía email al usuario para cambios CRITICAL/HIGH.

    Anti-spam: STATUS_DOWN solo se notifica la primera vez (consecutive_failures == 0).
    """
    from django.core.mail import send_mail
    from django.template.loader import render_to_string

    ALERT_SEVERITIES = {"critical", "high"}
    alertable = [c for c in changes if c.severity in ALERT_SEVERITIES]
    if not alertable:
        return

    # Evitar spam: si el target ya estaba caído, no re-notificar status_down
    has_down = any(c.change_type == "status_down" for c in alertable)
    if has_down and target.consecutive_failures > 0:
        alertable = [c for c in alertable if c.change_type != "status_down"]
        if not alertable:
            return

    user = target.user
    context = {"user": user, "target": target, "changes": alertable}

    subject = render_to_string("email/monitor_alert_subject.txt", context).strip()
    body    = render_to_string("email/monitor_alert.txt", context)

    send_mail(
        subject=subject,
        message=body,
        from_email=None,
        recipient_list=[user.email],
        fail_silently=False,
    )
    logger.info(
        "Monitor alert → %s | target '%s' | %d change(s)",
        user.email, target.name, len(alertable),
    )
