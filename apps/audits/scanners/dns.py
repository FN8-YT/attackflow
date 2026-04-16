"""
DNS scanner.

Resuelve el hostname a todas sus IPs (v4 y v6) y hace reverse lookup
informativo. No genera findings de severidad alta porque el grueso
ya lo validó el módulo validators.py antes de crear el target.
"""
from __future__ import annotations

import socket

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult


class DnsScanner(BaseScanner):
    name = "dns"

    def run(self, context: ScanContext) -> ScanResult:
        target = context.target
        result = ScanResult()

        ipv4: list[str] = []
        ipv6: list[str] = []
        try:
            infos = socket.getaddrinfo(target.hostname, None)
            for family, *_, sockaddr in infos:
                ip = sockaddr[0]
                if family == socket.AF_INET and ip not in ipv4:
                    ipv4.append(ip)
                elif family == socket.AF_INET6 and ip not in ipv6:
                    ipv6.append(ip)
        except socket.gaierror as exc:
            result.raw["error"] = str(exc)
            return result

        # Reverse DNS (informativo, no crítico si falla).
        reverse = ""
        try:
            reverse, _aliases, _addrs = socket.gethostbyaddr(target.ip)
        except (socket.herror, socket.gaierror):
            reverse = ""

        result.raw = {
            "hostname": target.hostname,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "reverse_dns": reverse,
        }

        result.findings.append(
            self.finding(
                category=Category.DNS,
                severity=Severity.INFO,
                title="Resolución DNS completada",
                description=(
                    f"El host {target.hostname} resuelve a "
                    f"{len(ipv4)} IPv4 y {len(ipv6)} IPv6."
                ),
                evidence=result.raw,
            )
        )
        return result
