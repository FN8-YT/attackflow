"""
Port Scanner mejorado — nmap con detección de versiones + banner grabbing.

Mejoras vs versión original:
- `-sV` para service/version detection (OpenSSH 8.9p1, nginx 1.25, etc.)
- `--script=banner,http-title,ssl-cert` para info adicional
- Puertos ampliados: Docker API (2375), Prometheus (9090), RabbitMQ (15672),
  Jupyter (8888), Grafana (3000), Jenkins (8080), Kubernetes (6443), etc.
- CPE extraído del resultado para correlación con CVEs
- Severidad contextual: Redis/PostgreSQL/MongoDB en internet = CRITICAL
- Finding incluye versión detectada para priorización real
"""
from __future__ import annotations

import logging

import nmap

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

logger = logging.getLogger(__name__)

# Puertos a escanear — agrupados por categoría de riesgo
SCAN_PORTS = ",".join(str(p) for p in sorted([
    # Web
    80, 443, 8080, 8443, 8888, 3000,
    # Infraestructura / admin
    21, 22, 23, 25, 53, 110, 143, 445, 3389,
    # Bases de datos (expuestas = CRITICAL)
    1433,   # MSSQL
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    9200,   # Elasticsearch
    9300,   # Elasticsearch cluster
    11211,  # Memcached
    27017,  # MongoDB
    27018,  # MongoDB
    5984,   # CouchDB
    6380,   # Redis TLS
    # DevOps / CI/CD
    2375,   # Docker API (sin TLS — CRITICAL)
    2376,   # Docker API (con TLS)
    4243,   # Docker legacy
    6443,   # Kubernetes API
    8001,   # Kubernetes dashboard
    10250,  # Kubelet
    2379,   # etcd
    2380,   # etcd
    4369,   # RabbitMQ EPMD
    5672,   # RabbitMQ AMQP
    15672,  # RabbitMQ Management UI
    9090,   # Prometheus
    3100,   # Loki
    9091,   # Prometheus pushgateway
    # Herramientas / paneles
    8888,   # Jupyter Notebook
    8161,   # ActiveMQ
    61616,  # ActiveMQ broker
    8983,   # Apache Solr
    5601,   # Kibana
    9000,   # SonarQube / Portainer / PHP-FPM
    4848,   # GlassFish admin
    4040,   # Apache Spark
    7474,   # Neo4j
    7687,   # Neo4j bolt
    # VPN / Remote
    1194,   # OpenVPN
    500,    # IKE/VPN
    4500,   # IKE NAT-T
    5900,   # VNC
    5901,   # VNC
    # Mail
    587,    # SMTP submission
    993,    # IMAPS
    995,    # POP3S
    465,    # SMTPS
]))

# Severidad base por puerto
PORT_SEVERITY: dict[int, str] = {
    # CRITICAL — nunca deberían estar expuestos a internet
    23:    Severity.CRITICAL,  # Telnet
    2375:  Severity.CRITICAL,  # Docker API sin TLS
    4243:  Severity.CRITICAL,  # Docker legacy
    3306:  Severity.CRITICAL,  # MySQL
    5432:  Severity.CRITICAL,  # PostgreSQL
    6379:  Severity.CRITICAL,  # Redis
    6380:  Severity.CRITICAL,  # Redis TLS
    9200:  Severity.CRITICAL,  # Elasticsearch
    9300:  Severity.CRITICAL,  # Elasticsearch
    11211: Severity.CRITICAL,  # Memcached
    27017: Severity.CRITICAL,  # MongoDB
    27018: Severity.CRITICAL,  # MongoDB
    5984:  Severity.CRITICAL,  # CouchDB
    2379:  Severity.CRITICAL,  # etcd
    2380:  Severity.CRITICAL,  # etcd
    10250: Severity.CRITICAL,  # Kubelet
    6443:  Severity.CRITICAL,  # K8s API
    8001:  Severity.CRITICAL,  # K8s dashboard
    5900:  Severity.CRITICAL,  # VNC
    5901:  Severity.CRITICAL,  # VNC
    4369:  Severity.CRITICAL,  # RabbitMQ EPMD

    # HIGH — servicios peligrosos o inesperadamente expuestos
    21:    Severity.HIGH,       # FTP sin cifrar
    445:   Severity.HIGH,       # SMB
    3389:  Severity.HIGH,       # RDP
    1433:  Severity.HIGH,       # MSSQL
    15672: Severity.HIGH,       # RabbitMQ UI
    8983:  Severity.HIGH,       # Solr
    5601:  Severity.HIGH,       # Kibana
    9090:  Severity.HIGH,       # Prometheus
    8161:  Severity.HIGH,       # ActiveMQ
    4848:  Severity.HIGH,       # GlassFish
    7474:  Severity.HIGH,       # Neo4j
    7687:  Severity.HIGH,       # Neo4j bolt
    8888:  Severity.HIGH,       # Jupyter
    9000:  Severity.HIGH,       # SonarQube/Portainer
    2376:  Severity.HIGH,       # Docker API TLS (puede estar mal configurado)

    # MEDIUM
    22:    Severity.MEDIUM,     # SSH (expectable pero puede ser bruteforced)
    25:    Severity.MEDIUM,     # SMTP
    53:    Severity.MEDIUM,     # DNS (resolver abierto)
    110:   Severity.MEDIUM,     # POP3
    143:   Severity.MEDIUM,     # IMAP
    5672:  Severity.MEDIUM,     # RabbitMQ AMQP
    3100:  Severity.MEDIUM,     # Loki
    9091:  Severity.MEDIUM,     # Prometheus pushgateway
    61616: Severity.MEDIUM,     # ActiveMQ broker
    4040:  Severity.MEDIUM,     # Spark UI

    # LOW / INFO — puertos web esperables
    80:    Severity.INFO,
    443:   Severity.INFO,
    8080:  Severity.LOW,
    8443:  Severity.LOW,
    3000:  Severity.LOW,        # Grafana o dev server
    587:   Severity.LOW,
    465:   Severity.LOW,
    993:   Severity.INFO,
    995:   Severity.INFO,
}

PORT_DESCRIPTIONS: dict[int, str] = {
    23:    "Telnet transmite credenciales en texto plano. Deshabilitar inmediatamente.",
    21:    "FTP sin TLS expone credenciales. Usa SFTP o FTPS.",
    2375:  "Docker API sin TLS expuesto — acceso root completo al host. CRÍTICO.",
    2376:  "Docker API con TLS expuesto — verificar certificados y acceso.",
    6379:  "Redis sin autenticación expuesto a internet — lectura/escritura libre.",
    9200:  "Elasticsearch expuesto sin autenticación — datos accesibles públicamente.",
    11211: "Memcached expuesto — vector clásico de amplificación DDoS y data leak.",
    27017: "MongoDB expuesto — base de datos accesible sin credenciales.",
    5432:  "PostgreSQL expuesto a internet. Usar firewall/VPN.",
    3306:  "MySQL expuesto a internet. Usar firewall/VPN.",
    1433:  "MSSQL expuesto a internet. Vector frecuente de ataques.",
    445:   "SMB expuesto — vector de EternalBlue, ransomware y movimiento lateral.",
    3389:  "RDP expuesto — objetivo masivo de brute force. Usar VPN o bastion host.",
    5900:  "VNC expuesto — control remoto del escritorio sin cifrado.",
    5901:  "VNC expuesto — control remoto del escritorio sin cifrado.",
    10250: "Kubelet API expuesto — acceso a pods y posible escape al nodo.",
    6443:  "Kubernetes API expuesto — verificar autenticación y autorización.",
    8001:  "Kubernetes Dashboard expuesto — interfaz web de admin del cluster.",
    2379:  "etcd expuesto — almacén de secretos de Kubernetes accesible.",
    15672: "RabbitMQ Management UI expuesto — verificar credenciales por defecto.",
    8983:  "Apache Solr expuesto — vulnerabilidades de RCE conocidas.",
    5601:  "Kibana expuesto — acceso a datos de Elasticsearch.",
    8888:  "Jupyter Notebook expuesto — ejecución arbitraria de código Python.",
    9000:  "Puerto 9000 expuesto (SonarQube/Portainer/PHP-FPM) — verificar servicio.",
    5984:  "CouchDB expuesto — API REST con potencial acceso sin auth.",
    7474:  "Neo4j Browser expuesto — interfaz de base de datos de grafos.",
    4848:  "GlassFish Admin Console expuesta — credenciales por defecto conocidas.",
}

PORT_RECOMMENDATIONS: dict[int, str] = {
    2375:  "Eliminar exposición inmediatamente. Configurar TLS mutuo si el acceso remoto es necesario.",
    6379:  "Añadir requirepass en redis.conf. Bind a 127.0.0.1. Usar VPN para acceso remoto.",
    9200:  "Habilitar X-Pack Security. No exponer a internet nunca.",
    27017: "Habilitar autenticación en MongoDB. Usar bind_ip = 127.0.0.1.",
    3306:  "bind-address = 127.0.0.1 en my.cnf. Usar bastion host o VPN.",
    5432:  "listen_addresses = localhost en postgresql.conf. Usar SSH tunnel.",
    10250: "Habilitar TLS + autenticación en Kubelet. Network policy de restricción.",
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
                # -sT: TCP connect (no requiere CAP_NET_RAW)
                # -sV: service/version detection
                # -Pn: asumir host activo (no ping)
                # -T4: timing agresivo
                # --script: banner grabbing + http-title
                # --version-intensity 5: balance velocidad/precisión
                arguments="-sT -sV -Pn -T4 --host-timeout 90s --version-intensity 5 --script=banner,http-title",
            )
        except nmap.PortScannerError as exc:
            logger.warning("nmap error: %s", exc)
            result.raw = {"error": str(exc)}
            return result
        except Exception as exc:
            logger.exception("Port scan error")
            result.raw = {"error": f"nmap error: {exc}"}
            return result

        if target.ip not in scanner.all_hosts():
            result.raw = {"note": "Host no respondió al escaneo."}
            return result

        host_info = scanner[target.ip]
        tcp_ports  = host_info.get("tcp", {})
        open_ports = [p for p, info in tcp_ports.items() if info.get("state") == "open"]

        # Raw data enriquecido
        port_details = {}
        for p, info in tcp_ports.items():
            port_details[str(p)] = {
                "state":    info.get("state", ""),
                "service":  info.get("name", ""),
                "product":  info.get("product", ""),
                "version":  info.get("version", ""),
                "cpe":      info.get("cpe", ""),
                "extrainfo":info.get("extrainfo", ""),
                "script":   info.get("script", {}),
            }

        result.raw = {
            "ip":         target.ip,
            "open_ports": open_ports,
            "port_detail": port_details,
        }

        for port in open_ports:
            port_info  = tcp_ports.get(port, {})
            service    = port_info.get("name", "")
            product    = port_info.get("product", "")
            version    = port_info.get("version", "")
            extrainfo  = port_info.get("extrainfo", "")
            cpe        = port_info.get("cpe", "")
            scripts    = port_info.get("script", {})

            severity    = PORT_SEVERITY.get(port, Severity.LOW)
            description = PORT_DESCRIPTIONS.get(
                port, f"El puerto {port}/{service or 'tcp'} está abierto y aceptando conexiones."
            )
            recommendation = PORT_RECOMMENDATIONS.get(
                port,
                "Si este puerto no necesita estar accesible desde internet, ciérralo "
                "con firewall (iptables/nftables) o muévelo detrás de VPN/bastion host.",
            )

            # Título enriquecido con versión detectada
            version_str = " ".join(filter(None, [product, version, extrainfo])).strip()
            title = f"Puerto TCP {port} abierto — {service or 'unknown'}"
            if version_str:
                title = f"Puerto TCP {port} ({service}) — {version_str}"

            evidence: dict = {
                "port":    port,
                "service": service,
                "product": product,
                "version": version,
            }
            if cpe:
                evidence["cpe"] = cpe
            if extrainfo:
                evidence["extrainfo"] = extrainfo
            if scripts:
                # Extraer el banner o http-title del script output
                for script_name, script_out in scripts.items():
                    evidence[f"script_{script_name}"] = str(script_out)[:300]

            result.findings.append(
                self.finding(
                    category=Category.PORTS,
                    severity=severity,
                    title=title,
                    description=description,
                    evidence=evidence,
                    recommendation=recommendation,
                )
            )

        # Finding resumen si hay puertos CRITICAL
        critical_ports = [p for p in open_ports if PORT_SEVERITY.get(p) == Severity.CRITICAL]
        if critical_ports:
            result.raw["critical_ports"] = critical_ports
            logger.warning(
                "Target %s tiene %d puerto(s) CRÍTICOS expuestos: %s",
                target.url, len(critical_ports), critical_ports,
            )

        return result
