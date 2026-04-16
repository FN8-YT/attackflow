"""
Scanner de SQL injection basado en errores.

MODO ACTIVO: inyecta payloads que intentan provocar errores de SQL
visibles en la respuesta. No intenta extraer datos — solo detecta
si la aplicación es potencialmente vulnerable.

Solo se ejecuta en modo 'active'.
"""
from __future__ import annotations

import logging
import re
import secrets
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from apps.audits.models import Category, Severity

from .base import BaseScanner, ScanContext, ScanResult

logger = logging.getLogger(__name__)

# Payloads clásicos de error-based SQLi.
SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1' AND 1=CONVERT(int,(SELECT @@version))--",
    "1 UNION SELECT NULL--",
    "') OR ('1'='1",
]

# Patrones de error de distintos DBMS.
ERROR_PATTERNS = [
    # MySQL
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning.*mysql", "MySQL"),
    (r"unclosed quotation mark", "MSSQL"),
    # PostgreSQL
    (r"pg_query\(\).*error", "PostgreSQL"),
    (r"unterminated quoted string", "PostgreSQL"),
    (r"syntax error at or near", "PostgreSQL"),
    # MSSQL
    (r"microsoft ole db provider for sql server", "MSSQL"),
    (r"\[microsoft\]\[odbc sql server driver\]", "MSSQL"),
    (r"mssql_query\(\)", "MSSQL"),
    # Oracle
    (r"ora-\d{5}", "Oracle"),
    (r"oracle.*driver", "Oracle"),
    # SQLite
    (r"sqlite3\.operationalerror", "SQLite"),
    (r"unrecognized token", "SQLite"),
    # Genéricos
    (r"sql syntax.*error", "Unknown DB"),
    (r"invalid query", "Unknown DB"),
    (r"odbc.*driver", "Unknown DB"),
]

COMMON_PARAMS = ("id", "page", "cat", "item", "product", "user", "order", "q", "search")
SQLI_TIMEOUT = 10


class SqliScanner(BaseScanner):
    name = "sqli"

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        target = context.target
        parsed = urlparse(target.url)

        existing_params = parse_qs(parsed.query, keep_blank_values=True)
        if existing_params:
            params_to_test = list(existing_params.keys())[:5]
        else:
            params_to_test = list(COMMON_PARAMS[:4])

        nonce = secrets.token_hex(4)
        vulnerable: list[dict] = []
        tested = 0

        # Obtener baseline — respuesta normal para comparar.
        baseline_errors = set()
        if context.has_http:
            baseline_body = context.body_text.lower()
            for pattern, db in ERROR_PATTERNS:
                if re.search(pattern, baseline_body, re.IGNORECASE):
                    baseline_errors.add(pattern)

        for param in params_to_test:
            found_for_param = False
            for payload in SQLI_PAYLOADS:
                if found_for_param:
                    break
                test_params = dict(existing_params)
                test_params[param] = [payload]

                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    urlencode(test_params, doseq=True),
                    "",
                ))

                tested += 1
                try:
                    resp = requests.get(
                        test_url,
                        timeout=SQLI_TIMEOUT,
                        allow_redirects=True,
                        headers={"User-Agent": "SecurityAuditBot/0.1"},
                    )
                    body = resp.text.lower()

                    for pattern, db_name in ERROR_PATTERNS:
                        if pattern in baseline_errors:
                            continue  # Ya estaba en la respuesta normal.
                        if re.search(pattern, body, re.IGNORECASE):
                            vulnerable.append({
                                "param": param,
                                "payload": payload,
                                "db_hint": db_name,
                                "error_pattern": pattern,
                                "status_code": resp.status_code,
                            })
                            found_for_param = True
                            break
                except requests.RequestException:
                    continue

        result.raw = {
            "params_tested": params_to_test,
            "payloads_sent": tested,
            "vulnerabilities_found": len(vulnerable),
        }

        if vulnerable:
            for vuln in vulnerable:
                result.findings.append(
                    self.finding(
                        category=Category.VULNS,
                        severity=Severity.CRITICAL,
                        title=f"Posible SQL Injection en parámetro '{vuln['param']}'",
                        description=(
                            f"El parámetro '{vuln['param']}' provoca un error de "
                            f"base de datos ({vuln['db_hint']}) al recibir un payload "
                            "de inyección SQL. Esto indica que el input del usuario "
                            "se concatena directamente en consultas SQL."
                        ),
                        evidence={
                            "param": vuln["param"],
                            "payload": vuln["payload"],
                            "database": vuln["db_hint"],
                        },
                        recommendation=(
                            "Usa SIEMPRE consultas parametrizadas (prepared statements). "
                            "Nunca concatenes input del usuario en consultas SQL. "
                            "Implementa un WAF como capa adicional de defensa."
                        ),
                        reference_url="https://owasp.org/www-community/attacks/SQL_Injection",
                    )
                )
        else:
            result.findings.append(
                self.finding(
                    category=Category.VULNS,
                    severity=Severity.INFO,
                    title="No se detectó SQL injection basado en errores",
                    description=(
                        f"Se probaron {tested} payloads en {len(params_to_test)} "
                        "parámetros sin detectar errores de base de datos inducidos."
                    ),
                )
            )

        return result
