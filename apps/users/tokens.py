"""
Token de verificación de email.

Diseño: django.core.signing.TimestampSigner — stateless, sin tabla extra.

Por qué signing y no un UUIDField en BD:
  - No requiere limpieza periódica de tokens expirados.
  - HMAC-SHA256 incorporado: imposible falsificar sin SECRET_KEY.
  - Expiración nativa (max_age) en el propio decode.
  - Incluir email en el payload invalida el token si el usuario
    cambia su dirección antes de verificarla.
  - Una vez is_verified=True, la vista rechaza el token aunque sea válido
    (no puede reutilizarse para "reverificar").

Flujo de expiración:
  - TOKEN_MAX_AGE (default 24h) configurable via settings.EMAIL_VERIFY_MAX_AGE.
  - Pasado ese tiempo, signing.loads() lanza SignatureExpired → None.
"""
from __future__ import annotations

import logging

from django.conf import settings
from django.core import signing

logger = logging.getLogger(__name__)

# Salt único para este uso. Cambiar el salt invalida todos los tokens
# pendientes (útil para rotación de emergencia).
_SALT = "attackflow.email-verification.v1"

# Ventana de validez: 24 horas por defecto.
TOKEN_MAX_AGE: int = getattr(settings, "EMAIL_VERIFY_MAX_AGE", 60 * 60 * 24)


def make_verification_token(user) -> str:
    """
    Genera un token firmado con timestamp para el usuario dado.

    El payload {pk, email} garantiza que si el email cambia antes de
    verificar, el token queda inválido automáticamente.
    """
    payload = {"pk": user.pk, "email": user.email}
    return signing.dumps(payload, salt=_SALT)


def verify_verification_token(token: str):
    """
    Valida el token.

    Retorna el User si el token es válido, no ha expirado y el usuario
    existe con ese pk+email. Retorna None en cualquier otro caso.

    No lanza excepciones — el caller solo necesita saber si es None o User.
    """
    from apps.users.models import User  # import tardío para evitar ciclos

    try:
        payload = signing.loads(token, salt=_SALT, max_age=TOKEN_MAX_AGE)
    except signing.SignatureExpired:
        logger.info("Verification token expired.")
        return None
    except signing.BadSignature:
        logger.warning("Verification token bad signature — possible tampering.")
        return None
    except Exception:
        logger.exception("Unexpected error decoding verification token.")
        return None

    try:
        return User.objects.get(pk=payload["pk"], email=payload["email"])
    except (User.DoesNotExist, KeyError):
        logger.warning(
            "Verification token references unknown user pk=%s",
            payload.get("pk"),
        )
        return None
