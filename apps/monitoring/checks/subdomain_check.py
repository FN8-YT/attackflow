"""
Subdomain discovery para Attack Surface.

Prueba ~60 subdominios comunes con DNS + HTTP HEAD en paralelo.
Devuelve una lista de dicts con información de cada subdominio activo/inactivo.

Diseño:
- Resolución DNS primero (socket.getaddrinfo) para filtrar inexistentes rápido.
- HEAD request con timeout corto (4s) a los que resuelven.
- ThreadPoolExecutor con max_workers=20 para paralelismo.
- Solo IPs públicas (descarta RFC-1918 y loopback).
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# ── Subdominios a probar ─────────────────────────────────────────────────────
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "ns1", "ns2", "ns3", "ns4", "mx", "mx1", "mx2",
    "dev", "develop", "development", "staging", "stage", "pre",
    "api", "api2", "api3", "v1", "v2", "rest",
    "admin", "administrator", "portal", "dashboard", "panel", "cpanel", "whm",
    "cdn", "static", "assets", "media", "img", "images", "files",
    "blog", "news", "shop", "store", "ecommerce", "cart",
    "app", "apps", "mobile", "m", "wap",
    "vpn", "remote", "rdp", "ssh",
    "git", "gitlab", "github", "svn", "bitbucket",
    "jenkins", "ci", "cd", "build",
    "jira", "confluence", "wiki", "kb", "docs", "help", "support",
    "status", "monitor", "uptime", "health", "metrics", "grafana", "kibana",
    "test", "qa", "uat", "demo", "beta", "alpha", "sandbox",
    "secure", "login", "auth", "sso", "id", "accounts", "oauth",
    "intranet", "internal", "extranet", "corp", "office",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "backup", "old", "new", "legacy", "archive",
    "phpmyadmin", "adminer", "pma",
]

UA = "AttackFlow-Monitor/1.0 (Attack Surface Scanner)"
HEAD_TIMEOUT = 4


def _is_public_ip(ip_str: str) -> bool:
    """Devuelve True solo para IPs públicas (descarta RFC-1918, loopback, link-local)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            not addr.is_private
            and not addr.is_loopback
            and not addr.is_link_local
            and not addr.is_unspecified
            and not addr.is_multicast
        )
    except ValueError:
        return False


def _resolve_hostname(hostname: str) -> str | None:
    """Resuelve hostname a IP. Retorna None si falla o IP es privada."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        for *_, (ip, _) in results:
            if _is_public_ip(ip):
                return ip
        return None  # Resolvió pero solo IPs privadas
    except socket.gaierror:
        return None


def _probe_subdomain(subdomain: str, hostname: str, schemes: list[str]) -> dict | None:
    """
    Intenta HEAD a http(s)://hostname. Retorna dict o None si no hay respuesta.
    """
    ip = _resolve_hostname(hostname)
    if not ip:
        return None

    for scheme in schemes:
        url = f"{scheme}://{hostname}"
        try:
            import time
            t0 = time.monotonic()
            resp = requests.head(
                url,
                timeout=HEAD_TIMEOUT,
                headers={"User-Agent": UA},
                allow_redirects=True,
            )
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            return {
                "subdomain":        subdomain,
                "hostname":         hostname,
                "ip_address":       ip,
                "is_active":        True,
                "http_status_code": resp.status_code,
                "response_time_ms": elapsed_ms,
            }
        except requests.exceptions.SSLError:
            # SSL error: el host existe pero el certificado falla — aún interesante
            return {
                "subdomain":        subdomain,
                "hostname":         hostname,
                "ip_address":       ip,
                "is_active":        True,
                "http_status_code": None,
                "response_time_ms": None,
            }
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            continue
        except requests.exceptions.RequestException:
            continue

    # DNS resolvió pero HTTP no respondió (puerto cerrado, FW)
    return {
        "subdomain":        subdomain,
        "hostname":         hostname,
        "ip_address":       ip,
        "is_active":        False,
        "http_status_code": None,
        "response_time_ms": None,
    }


def check_subdomains(base_url: str, max_workers: int = 20) -> list[dict]:
    """
    Descubre subdominios activos/inactivos para el dominio base de base_url.

    Retorna lista de dicts:
        subdomain, hostname, ip_address, is_active,
        http_status_code, response_time_ms
    """
    parsed = urlparse(base_url)
    hostname = parsed.hostname or ""
    if not hostname:
        return []

    # Extraer dominio base (quitar 'www.' si existe)
    # Ej: www.example.com → example.com; api.staging.example.com → example.com (solo 2 niveles)
    parts = hostname.split(".")
    if len(parts) >= 2:
        base_domain = ".".join(parts[-2:])
    else:
        base_domain = hostname

    # Esquemas según si la URL base es https o http
    schemes = ["https", "http"] if parsed.scheme == "https" else ["http", "https"]

    results: list[dict] = []
    futures = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{base_domain}"
            if fqdn == hostname:
                continue  # no re-probar el host base
            future = executor.submit(_probe_subdomain, sub, fqdn, schemes)
            futures[future] = sub

        for future in as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
            except Exception as exc:
                logger.debug("Subdomain probe error (%s): %s", futures[future], exc)

    # Ordenar: activos primero, luego por hostname
    results.sort(key=lambda r: (not r["is_active"], r["hostname"]))
    return results
