"""
Port scanner basado en nmap.

Notas de implementación:
- Usamos `-sT` (TCP connect) en vez del SYN por defecto porque:
  1) No requiere CAP_NET_RAW en el contenedor.
  2) Es el comportamiento de cualquier cliente TCP normal → menos
     probabilidad de que firewalls lo marquen como escaneo hostil.
- Solo escaneamos un conjunto pequeño de puertos conocidos, no el
  rango completo. Un escaneo full /65535 tarda minutos y es abusivo.
- Timeout agresivo (-T4) y `--host-timeout` para no colgarse.
- Clasificamos los puertos abiertos por riesgo: un 80/443 abierto es
  esperado; un 3306/6379 abierto desde internet es crítico.
"""
from __future__ import annotations

import nmap  # python-nmap

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

# Subconjunto relevante: web, infraestructura expuesta por error, BBDD.
SCAN_PORTS = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,11211,27017"

# Severidad esperada si el puerto aparece como open.
PORT_SEVERITY: dict[int, str] = {
    21: Severity.HIGH,        # FTP
    22: Severity.INFO,        # SSH (esperable)
    23: Severity.CRITICAL,    # Telnet (sin cifrado)
    25: Severity.MEDIUM,      # SMTP
    53: Severity.LOW,         # DNS
    80: Severity.INFO,        # HTTP
    110: Severity.MEDIUM,     # POP3
    143: Severity.MEDIUM,     # IMAP
    443: Severity.INFO,       # HTTPS
    445: Severity.HIGH,       # SMB
    3306: Severity.CRITICAL,  # MySQL
    3389: Severity.HIGH,      # RDP
    5432: Severity.CRITICAL,  # PostgreSQL
    6379: Severity.CRITICAL,  # Redis
    8080: Severity.LOW,       # HTTP alt
    8443: Severity.LOW,       # HTTPS alt
    9200: Severity.CRITICAL,  # Elasticsearch
    11211: Severity.CRITICAL, # Memcached
    27017: Severity.CRITICAL, # MongoDB
}

PORT_DESCRIPTIONS: dict[int, str] = {
    23: "Telnet transmite credenciales en texto plano. Desactívalo.",
    21: "FTP sin TLS expone credenciales. Usa SFTP o FTPS.",
    3306: "MySQL no debería estar expuesto a internet. Usa firewall o VPN.",
    5432: "PostgreSQL no debería estar expuesto a internet. Usa firewall o VPN.",
    6379: "Redis no debería estar expuesto a internet. Usa firewall o VPN.",
    9200: "Elasticsearch no debería estar expuesto sin autenticación.",
    11211: "Memcached no debería estar expuesto; vector clásico de amplificación.",
    27017: "MongoDB no debería estar expuesto a internet.",
    445: "SMB expuesto es vector de ataques tipo EternalBlue.",
    3389: "RDP expuesto es objetivo de brute force. Usa VPN o bastion.",
}


class PortsScanner(BaseScanner):
    name = "ports"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        target = context.target

        scanner = nmap.PortScanner()
        try:
            scanner.scan(
                hosts=target.ip,
                ports=SCAN_PORTS,
                arguments="-sT -Pn -T4 --host-timeout 60s",
            )
        except nmap.PortScannerError as exc:
            result.raw = {"error": str(exc)}
            return result
        except Exception as exc:
            result.raw = {"error": f"nmap error: {exc}"}
            return result

        if target.ip not in scanner.all_hosts():
            result.raw = {"note": "Host no respondió al escaneo."}
            return result

        host_info = scanner[target.ip]
        tcp_ports = host_info.get("tcp", {})
        open_ports = [p for p, info in tcp_ports.items() if info.get("state") == "open"]

        result.raw = {
            "ip": target.ip,
            "open_ports": open_ports,
            "tcp_detail": {str(p): info for p, info in tcp_ports.items()},
        }

        for port in open_ports:
            severity = PORT_SEVERITY.get(port, Severity.LOW)
            description = PORT_DESCRIPTIONS.get(
                port, f"El puerto {port} está abierto y aceptando conexiones."
            )
            result.findings.append(
                self.finding(
                    category=Category.PORTS,
                    severity=severity,
                    title=f"Puerto TCP {port} abierto",
                    description=description,
                    evidence={"port": port, "service": tcp_ports[port].get("name", "")},
                    recommendation=(
                        "Si este puerto no necesita estar accesible desde internet, "
                        "ciérralo con firewall o muévelo detrás de VPN."
                    ),
                )
            )

        return result
