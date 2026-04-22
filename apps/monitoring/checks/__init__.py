"""Módulos de análisis de monitoring para pentesters."""
from .tech_detection import detect_technologies
from .waf_detection import detect_waf
from .sensitive_paths import check_sensitive_paths
from .scoring import calculate_security_score, score_grade
from .subdomain_check import check_subdomains
from .screenshot import process_screenshot

__all__ = [
    "detect_technologies",
    "detect_waf",
    "check_sensitive_paths",
    "calculate_security_score",
    "score_grade",
    "check_subdomains",
    "process_screenshot",
]
