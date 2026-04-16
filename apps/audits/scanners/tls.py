"""
TLS/SSL scanner.

Qué comprueba:
- Certificado válido (cadena, CA conocida, hostname match).
- Fecha de expiración.
- Emisor y sujeto.
- Versión del protocolo TLS negociada.

Implementación:
- Usamos ssl + socket de stdlib para negociar y extraer el certificado
  en forma binaria (DER), y cryptography para parsearlo sin importar
  si la validación pasó o falló.
- Dos intentos: uno estricto para saber si un cliente normal lo aceptaría,
  y otro permisivo para poder inspeccionar el cert aunque sea inválido.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

TLS_CONNECT_TIMEOUT = 10  # segundos


class TlsScanner(BaseScanner):
    name = "tls"

    def run(self, context: ScanContext) -> ScanResult:
        target = context.target
        result = ScanResult()

        # Si el usuario envió http://, flag crítico y no seguimos.
        if not target.is_https:
            result.findings.append(
                self.finding(
                    category=Category.TRANSPORT,
                    severity=Severity.CRITICAL,
                    title="Sitio accesible sobre HTTP sin cifrar",
                    description=(
                        "La URL analizada usa http:// en lugar de https://. "
                        "Toda la comunicación viaja en texto plano y es "
                        "interceptable."
                    ),
                    recommendation=(
                        "Migra todo el tráfico a HTTPS y publica HSTS. "
                        "Redirige http → https con 301."
                    ),
                    reference_url="https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                )
            )
            result.raw = {"https": False}
            return result

        port = target.port if target.port != 80 else 443

        # --- Paso 1: validación estricta ---
        strict_ok = True
        strict_error = ""
        negotiated_version = ""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection(
                (target.hostname, port), timeout=TLS_CONNECT_TIMEOUT
            ) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=target.hostname) as tls_sock:
                    negotiated_version = tls_sock.version() or ""
        except ssl.SSLCertVerificationError as exc:
            strict_ok = False
            strict_error = f"Certificado no válido: {exc.reason}"
        except ssl.SSLError as exc:
            strict_ok = False
            strict_error = f"Error TLS: {exc}"
        except (OSError, socket.timeout) as exc:
            result.raw = {"error": str(exc)}
            return result

        # --- Paso 2: obtener el cert en binario (siempre, para inspeccionarlo) ---
        der_cert = None
        try:
            permissive = ssl.create_default_context()
            permissive.check_hostname = False
            permissive.verify_mode = ssl.CERT_NONE
            with socket.create_connection(
                (target.hostname, port), timeout=TLS_CONNECT_TIMEOUT
            ) as raw_sock:
                with permissive.wrap_socket(raw_sock, server_hostname=target.hostname) as tls_sock:
                    der_cert = tls_sock.getpeercert(binary_form=True)
                    if not negotiated_version:
                        negotiated_version = tls_sock.version() or ""
        except Exception as exc:
            result.raw = {"error": f"No se pudo obtener el certificado: {exc}"}
            return result

        # --- Paso 3: parseo con cryptography ---
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
        issuer = _name_to_str(cert.issuer)
        subject = _name_to_str(cert.subject)
        now = datetime.now(tz=timezone.utc)
        days_remaining = (not_after - now).days

        result.raw = {
            "https": True,
            "valid_chain": strict_ok,
            "validation_error": strict_error,
            "issuer": issuer,
            "subject": subject,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_remaining": days_remaining,
            "tls_version": negotiated_version,
        }

        # --- Findings ---
        if not strict_ok:
            result.findings.append(
                self.finding(
                    category=Category.TRANSPORT,
                    severity=Severity.HIGH,
                    title="Certificado TLS inválido",
                    description=strict_error,
                    evidence={"issuer": issuer, "subject": subject},
                    recommendation="Renueva o corrige la cadena de certificados.",
                )
            )

        # Expiración
        if now > not_after:
            result.findings.append(
                self.finding(
                    category=Category.TRANSPORT,
                    severity=Severity.CRITICAL,
                    title="Certificado TLS expirado",
                    description=f"Expiró el {not_after.isoformat()}.",
                    evidence={"not_after": not_after.isoformat()},
                )
            )
        elif days_remaining < 14:
            result.findings.append(
                self.finding(
                    category=Category.TRANSPORT,
                    severity=Severity.HIGH,
                    title="Certificado TLS a punto de expirar",
                    description=f"Quedan {days_remaining} días.",
                )
            )
        elif days_remaining < 30:
            result.findings.append(
                self.finding(
                    category=Category.TRANSPORT,
                    severity=Severity.MEDIUM,
                    title="Certificado TLS expira pronto",
                    description=f"Quedan {days_remaining} días.",
                )
            )

        # Protocolo antiguo
        if negotiated_version in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
            result.findings.append(
                self.finding(
                    category=Category.TRANSPORT,
                    severity=Severity.HIGH,
                    title=f"Protocolo TLS obsoleto: {negotiated_version}",
                    description=(
                        f"El servidor aceptó {negotiated_version}, "
                        "considerado inseguro."
                    ),
                    recommendation="Habilita solo TLS 1.2 y TLS 1.3.",
                    reference_url="https://wiki.mozilla.org/Security/Server_Side_TLS",
                )
            )

        return result


def _name_to_str(name: x509.Name) -> str:
    parts = []
    for oid, label in [
        (NameOID.COMMON_NAME, "CN"),
        (NameOID.ORGANIZATION_NAME, "O"),
        (NameOID.COUNTRY_NAME, "C"),
    ]:
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            parts.append(f"{label}={attrs[0].value}")
    return ", ".join(parts)
