"""
Validación de URL para auditoría.

Este módulo es el escudo anti-SSRF del sistema. Cualquier URL que
escanee el motor pasa primero por aquí.

Vectores bloqueados:
- Esquemas que no sean http/https (file://, gopher://, ftp://...).
- Puertos sospechosos (no estándar en el contexto web) opcionalmente
  bloqueados: aquí solo dejamos pasar 80/443 + el implícito.
- Hostnames que resuelven a IPs privadas, loopback, link-local,
  reservadas o multicast.
- Hostnames literales tipo "localhost" (resolución explícita).

Limitación conocida (se aborda mejor en Fase 6):
- DNS rebinding: entre el momento en que validamos y el momento en que
  conectamos, la IP puede cambiar. La mitigación completa es connect-by-IP
  con Host header. Lo dejamos anotado para no olvidarlo.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import ParseResult, urlparse

from django.core.exceptions import ValidationError

# Por seguridad restringimos el esquema a http/https.
ALLOWED_SCHEMES = frozenset({"http", "https"})

# Puerto por defecto por esquema si el usuario no lo especificó.
DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class ScanTarget:
    """Representación inmutable del objetivo validado."""

    url: str                  # URL original tal cual la envió el usuario
    parsed: ParseResult       # urlparse result
    hostname: str             # Hostname en minúsculas
    ip: str                   # IP resuelta (la primera pública)
    port: int                 # Puerto efectivo
    scheme: str               # http | https

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.hostname}:{self.port}"


def _is_public_ip(ip: ipaddress._BaseAddress) -> bool:
    """True solo si la IP es ruteable públicamente."""
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def resolve_and_validate(url: str) -> ScanTarget:
    """
    Valida y resuelve una URL. Lanza ValidationError en cualquier caso
    sospechoso. El mensaje de error es apto para mostrar al usuario.
    """
    if not url or not isinstance(url, str):
        raise ValidationError("URL vacía o inválida.")

    parsed = urlparse(url.strip())

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValidationError(
            f"Solo se permiten URLs http/https. Has enviado: {parsed.scheme!r}"
        )

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValidationError("La URL no contiene hostname.")

    # Bloqueo por nombre, antes incluso de resolver DNS.
    if hostname in {"localhost", "localhost.localdomain", "ip6-localhost"}:
        raise ValidationError("No se permiten hostnames locales.")

    # Si el usuario puso directamente una IP, la validamos sin DNS.
    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        if not _is_public_ip(literal_ip):
            raise ValidationError(
                f"La IP {literal_ip} no es pública (privada/loopback/reservada)."
            )
        ip_str = str(literal_ip)
    else:
        # Resolución DNS.
        try:
            addrinfo = socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            raise ValidationError(
                f"No se pudo resolver el hostname {hostname}: {exc.strerror}"
            ) from exc

        public_ip: str | None = None
        for _family, _type, _proto, _canon, sockaddr in addrinfo:
            candidate = ipaddress.ip_address(sockaddr[0])
            if not _is_public_ip(candidate):
                raise ValidationError(
                    f"El host {hostname} resuelve a {candidate}, "
                    "que no es una IP pública. No se permite."
                )
            # Preferimos IPv4 por compatibilidad con nmap,
            # pero si solo hay IPv6, usaremos IPv6.
            if candidate.version == 4 and public_ip is None:
                public_ip = str(candidate)
            elif public_ip is None:
                public_ip = str(candidate)

        if public_ip is None:
            raise ValidationError(f"No se obtuvieron IPs para {hostname}.")
        ip_str = public_ip

    port = parsed.port or DEFAULT_PORTS[parsed.scheme]
    if not (1 <= port <= 65535):
        raise ValidationError(f"Puerto fuera de rango: {port}")

    return ScanTarget(
        url=url,
        parsed=parsed,
        hostname=hostname,
        ip=ip_str,
        port=port,
        scheme=parsed.scheme,
    )
