"""
Monitoring Service — lógica de comprobación y detección de cambios.

Diseño:
- run_check(target): ejecuta una comprobación y devuelve MonitorCheck.
- _detect_changes(target, old, new): compara dos checks y crea MonitorChange.
- _send_alert_email(target, changes): envía email al usuario para cambios
  CRITICAL/HIGH. Lógica anti-spam: STATUS_DOWN solo genera 1 email por
  incidente (no repite mientras siga caído).
- Lightweight: sin scanner completo. Solo HTTP uptime, headers, SSL, content hash.
- Anti-SSRF: reusa resolve_and_validate de audits.

Seguridad:
- La URL se valida antes de hacer requests.
- Timeout de 10s por request.
- Solo permite http/https a IPs públicas.
"""
from __future__ import annotations

import hashlib
import logging
import socket
import ssl
import datetime
from typing import Optional
from urllib.parse import urlparse

import requests
from django.utils import timezone

from apps.audits.validators import resolve_and_validate
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)

TIMEOUT = 10
UA = "AttackFlow-Monitor/1.0"

# Cabeceras de seguridad que se monitorean para detectar cambios.
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
]

# Umbral de alerta de expiración SSL.
SSL_WARN_DAYS = 30
SSL_CRITICAL_DAYS = 7

# Umbral de degradación de respuesta (ms).
SLOW_RESPONSE_MS = 3000


def run_check(target) -> "MonitorCheck":
    """
    Ejecuta una comprobación completa para un MonitorTarget.

    Retorna el MonitorCheck creado. Los MonitorChange se crean
    automáticamente si se detectan diferencias con el check anterior.
    """
    from apps.monitoring.models import MonitorCheck, CheckStatus, MonitorTarget

    try:
        scan_target = resolve_and_validate(target.url)
    except ValidationError as exc:
        check = MonitorCheck.objects.create(
            target=target,
            status=CheckStatus.ERROR,
            error_message=f"URL inválida o bloqueada por SSRF: {exc}",
        )
        _update_target_status(target, check)
        return check

    # --- HTTP probe ---
    http_data = _probe_http(target.url)

    # --- SSL probe ---
    ssl_data: dict = {}
    if scan_target.scheme == "https":
        ssl_data = _probe_ssl(scan_target.hostname, scan_target.port or 443)

    # Determine status.
    if http_data.get("error"):
        status = CheckStatus.DOWN if "Connection" in str(http_data.get("error","")) else CheckStatus.ERROR
    elif http_data.get("status_code", 0) >= 500:
        status = CheckStatus.DOWN
    elif http_data.get("status_code", 0) > 0:
        status = CheckStatus.UP
    else:
        status = CheckStatus.ERROR

    check = MonitorCheck.objects.create(
        target=target,
        status=status,
        http_status_code=http_data.get("status_code"),
        response_time_ms=http_data.get("response_ms"),
        headers_snapshot=http_data.get("headers", {}),
        content_hash=http_data.get("content_hash", ""),
        ssl_expiry_days=ssl_data.get("expiry_days"),
        ssl_issuer=ssl_data.get("issuer", "")[:256],
        ssl_fingerprint=ssl_data.get("fingerprint", "")[:128],
        error_message=http_data.get("error", "") or ssl_data.get("error", ""),
    )

    # Detect changes vs previous check.
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
    except Exception as exc:
        logger.warning("Change detection failed for target %s: %s", target.pk, exc)

    _update_target_status(target, check)
    return check


def _probe_http(url: str) -> dict:
    """GET the URL and return timing, status, key headers, content hash."""
    try:
        start = timezone.now()
        resp = requests.get(
            url,
            timeout=TIMEOUT,
            headers={"User-Agent": UA},
            allow_redirects=True,
        )
        ms = int((timezone.now() - start).total_seconds() * 1000)

        # Snapshot security headers.
        headers = {}
        for h in SECURITY_HEADERS:
            val = resp.headers.get(h, "")
            if val:
                headers[h] = val

        # Hash first 50KB of content.
        content = resp.text[:51200]
        content_hash = hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()

        return {
            "status_code": resp.status_code,
            "response_ms": ms,
            "headers": headers,
            "content_hash": content_hash,
        }
    except requests.exceptions.ConnectionError as exc:
        return {"error": f"Connection error: {exc}"}
    except requests.exceptions.Timeout:
        return {"error": "Request timed out"}
    except requests.exceptions.RequestException as exc:
        return {"error": f"Request error: {exc}"}


def _probe_ssl(hostname: str, port: int = 443) -> dict:
    """Get SSL cert info: expiry, issuer, fingerprint."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                bin_cert = ssock.getpeercert(binary_form=True)

        # Expiry.
        not_after = cert.get("notAfter", "")
        if not_after:
            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            exp = exp.replace(tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            expiry_days = (exp - now).days
        else:
            expiry_days = None

        # Issuer (flatten).
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        issuer = issuer_dict.get("organizationName", "") or issuer_dict.get("commonName", "")

        # SHA-256 fingerprint.
        fingerprint = hashlib.sha256(bin_cert).hexdigest()[:16] if bin_cert else ""

        return {
            "expiry_days": expiry_days,
            "issuer": issuer,
            "fingerprint": fingerprint,
        }
    except ssl.SSLError as exc:
        return {"error": f"SSL error: {exc}"}
    except (socket.timeout, socket.gaierror, OSError) as exc:
        return {"error": f"Connection error: {exc}"}
    except Exception as exc:
        logger.debug("SSL probe error for %s: %s", hostname, exc)
        return {"error": f"Error: {exc}"}


def _detect_changes(target, prev: "MonitorCheck", curr: "MonitorCheck") -> None:
    """
    Compara prev vs curr y crea MonitorChange por cada diferencia detectada.
    """
    from apps.monitoring.models import MonitorChange, ChangeType, ChangeSeverity

    changes = []

    # 1. Status transition.
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

    # 2. HTTP status code changed.
    if (prev.http_status_code and curr.http_status_code
            and prev.http_status_code != curr.http_status_code):
        changes.append(dict(
            change_type=ChangeType.HTTP_STATUS,
            severity=ChangeSeverity.HIGH if curr.http_status_code >= 400 else ChangeSeverity.MEDIUM,
            description=f"Código HTTP: {prev.http_status_code} → {curr.http_status_code}",
            old_value=str(prev.http_status_code),
            new_value=str(curr.http_status_code),
        ))

    # 3. Security headers diff.
    old_hdrs = prev.headers_snapshot or {}
    new_hdrs = curr.headers_snapshot or {}

    all_hdr_keys = set(old_hdrs) | set(new_hdrs)
    for hdr in all_hdr_keys:
        old_val = old_hdrs.get(hdr, "")
        new_val = new_hdrs.get(hdr, "")
        if old_val == new_val:
            continue
        if old_val and not new_val:
            changes.append(dict(
                change_type=ChangeType.HEADER_REMOVED,
                severity=ChangeSeverity.HIGH,
                description=f"Header eliminado: {hdr}",
                old_value=old_val[:300],
                new_value="",
            ))
        elif not old_val and new_val:
            changes.append(dict(
                change_type=ChangeType.HEADER_ADDED,
                severity=ChangeSeverity.INFO,
                description=f"Header añadido: {hdr}",
                old_value="",
                new_value=new_val[:300],
            ))
        else:
            changes.append(dict(
                change_type=ChangeType.HEADER_CHANGED,
                severity=ChangeSeverity.MEDIUM,
                description=f"Header modificado: {hdr}",
                old_value=old_val[:300],
                new_value=new_val[:300],
            ))

    # 4. SSL expiry warnings.
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

    # SSL fingerprint changed → cert renewed or replaced.
    if (prev.ssl_fingerprint and curr.ssl_fingerprint
            and prev.ssl_fingerprint != curr.ssl_fingerprint):
        changes.append(dict(
            change_type=ChangeType.SSL_EXPIRY_CHG,
            severity=ChangeSeverity.MEDIUM,
            description="Certificado SSL reemplazado o renovado",
            old_value=prev.ssl_fingerprint,
            new_value=curr.ssl_fingerprint,
        ))

    # 5. Content changed.
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

    # 6. Response time degradation.
    if (prev.response_time_ms and curr.response_time_ms
            and curr.response_time_ms > SLOW_RESPONSE_MS
            and curr.response_time_ms > prev.response_time_ms * 2):
        changes.append(dict(
            change_type=ChangeType.RESPONSE_SLOW,
            severity=ChangeSeverity.LOW,
            description=f"Tiempo de respuesta degradado: {prev.response_time_ms}ms → {curr.response_time_ms}ms",
            old_value=str(prev.response_time_ms),
            new_value=str(curr.response_time_ms),
        ))

    # Persist.
    created_changes = []
    for c in changes:
        created_changes.append(
            MonitorChange.objects.create(target=target, monitor_check=curr, **c)
        )

    # Alertas por email para cambios importantes.
    if created_changes:
        try:
            _send_alert_email(target, created_changes)
        except Exception as exc:
            logger.warning("No se pudo enviar alerta email para target %s: %s", target.pk, exc)


def _send_alert_email(target, changes: list) -> None:
    """
    Envía email al usuario para cambios CRITICAL/HIGH.

    Anti-spam:
    - Solo procesa cambios CRITICAL o HIGH.
    - Para STATUS_DOWN: solo envía email si el target NO estaba ya caído
      antes de este check (evita spam mientras sigue offline).
    - Los demás cambios críticos (SSL expiry, headers) siempre notifican.
    """
    from django.core.mail import send_mail
    from django.template.loader import render_to_string

    ALERT_SEVERITIES = {"critical", "high"}

    # Filtrar solo cambios importantes.
    alertable = [c for c in changes if c.severity in ALERT_SEVERITIES]
    if not alertable:
        return

    # Anti-spam para STATUS_DOWN: si consecutive_failures > 1, ya enviamos
    # alerta cuando se produjo el primer fallo. No repetir.
    # (consecutive_failures aún no se actualizó; se actualiza en _update_target_status
    #  que se llama después. Por eso usamos el valor actual del target.)
    has_down = any(c.change_type == "status_down" for c in alertable)
    if has_down and target.consecutive_failures > 0:
        # Ya estaba caído antes: filtrar STATUS_DOWN del lote actual.
        alertable = [c for c in alertable if c.change_type != "status_down"]
        if not alertable:
            return

    user = target.user
    context = {
        "user": user,
        "target": target,
        "changes": alertable,
    }

    subject = render_to_string("email/monitor_alert_subject.txt", context).strip()
    body_txt = render_to_string("email/monitor_alert.txt", context)

    send_mail(
        subject=subject,
        message=body_txt,
        from_email=None,   # DEFAULT_FROM_EMAIL de settings
        recipient_list=[user.email],
        fail_silently=False,
    )
    logger.info(
        "Monitor alert email sent to %s for target '%s' (%d change(s))",
        user.email, target.name, len(alertable),
    )


def _update_target_status(target, check: "MonitorCheck") -> None:
    """Actualiza el estado cacheado del target con los datos del último check."""
    from django.utils import timezone

    # Consecutive failures counter.
    if check.status == "up":
        consecutive_failures = 0
    else:
        consecutive_failures = target.consecutive_failures + 1

    # Uptime % (last 30 checks).
    from apps.monitoring.models import MonitorCheck
    recent = (
        MonitorCheck.objects
        .filter(target=target)
        .order_by("-created_at")[:30]
    )
    total = recent.count()
    up_count = sum(1 for c in recent if c.status == "up")
    uptime = round((up_count / total * 100), 2) if total else None

    target.current_status = check.status
    target.last_check_at = timezone.now()
    target.last_response_ms = check.response_time_ms
    target.last_http_status = check.http_status_code
    target.last_ssl_days = check.ssl_expiry_days
    target.consecutive_failures = consecutive_failures
    target.uptime_pct = uptime
    target.save(update_fields=[
        "current_status", "last_check_at", "last_response_ms",
        "last_http_status", "last_ssl_days", "consecutive_failures",
        "uptime_pct", "updated_at",
    ])
