"""
Screenshot + Visual Monitoring para MonitorTarget.

Toma una captura de pantalla del objetivo usando Playwright (Chromium headless)
y la compara con la anterior para detectar cambios visuales significativos.

Casos de uso:
  - Detección de defacement (cambio drástico en la página)
  - Monitorización visual de uptime (el 200 puede ser un error page)
  - Comparación antes/después de deployments

Diseño:
  - Almacena screenshot como base64 PNG en DB (evita complejidad de media files)
  - Diff de píxeles via Pillow + redimensionado a 640x480 (rápido, bajo coste)
  - Threshold configurable: >30% cambio = alerta de defacement
  - Si Playwright no está instalado, retorna None silenciosamente
  - Timeout estricto: 20s por captura
"""
from __future__ import annotations

import base64
import hashlib
import io
import logging

logger = logging.getLogger(__name__)

# Umbral de píxeles cambiados (%) para alertar como posible defacement
DEFACEMENT_THRESHOLD_PCT = 30.0

# Viewport por defecto
DEFAULT_WIDTH  = 1280
DEFAULT_HEIGHT = 800

# Resolución para el diff (más pequeño = más rápido)
DIFF_WIDTH  = 640
DIFF_HEIGHT = 480

UA = "AttackFlow-Monitor/1.0 (VisualMonitor)"


def _playwright_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except ImportError:
        return False


def take_screenshot(url: str, width: int = DEFAULT_WIDTH, height: int = DEFAULT_HEIGHT) -> bytes | None:
    """
    Toma una captura de pantalla del URL con Playwright Chromium.
    Retorna los bytes del PNG, o None si falla.
    """
    if not _playwright_available():
        logger.info("Playwright no disponible — screenshot omitido.")
        return None

    try:
        from playwright.sync_api import sync_playwright, Error as PlaywrightError

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-web-security",   # permite cargar recursos mixtos
                    "--ignore-certificate-errors",
                ],
            )
            context = browser.new_context(
                viewport={"width": width, "height": height},
                ignore_https_errors=True,
                user_agent=UA,
                java_script_enabled=True,
            )
            page = context.new_page()

            # Bloquear recursos pesados innecesarios para el screenshot
            page.route(
                "**/*.{mp4,webm,ogg,mp3,wav,gif}",
                lambda route: route.abort(),
            )

            try:
                page.goto(
                    url,
                    timeout=15_000,
                    wait_until="domcontentloaded",  # no esperar todos los recursos
                )
                # Pequeña pausa para que JS renderice
                page.wait_for_timeout(1500)
            except PlaywrightError:
                # Error de navegación (timeout, cert inválido...) — tomar screenshot igualmente
                pass

            screenshot_bytes = page.screenshot(
                type="png",
                full_page=False,  # solo viewport (no scroll infinito)
            )
            browser.close()
            return screenshot_bytes

    except Exception as exc:
        logger.warning("Screenshot falló para %s: %s", url, exc)
        return None


def compute_diff_pct(img1_bytes: bytes, img2_bytes: bytes) -> float:
    """
    Calcula el porcentaje de píxeles que cambiaron entre dos screenshots.

    Ambas imágenes se redimensionan a DIFF_WIDTH×DIFF_HEIGHT antes de comparar,
    lo que hace el diff rápido e independiente del viewport.

    Retorna 0.0 si hay cualquier error.
    """
    try:
        from PIL import Image, ImageChops

        img1 = Image.open(io.BytesIO(img1_bytes)).convert("RGB").resize(
            (DIFF_WIDTH, DIFF_HEIGHT), Image.LANCZOS
        )
        img2 = Image.open(io.BytesIO(img2_bytes)).convert("RGB").resize(
            (DIFF_WIDTH, DIFF_HEIGHT), Image.LANCZOS
        )

        diff = ImageChops.difference(img1, img2)
        pixels = list(diff.getdata())
        total  = len(pixels)

        # Un píxel "cambió" si algún canal difiere en > 10/255 (threshold de ruido)
        changed = sum(1 for r, g, b in pixels if max(r, g, b) > 10)
        return round(changed / total * 100, 2) if total else 0.0

    except ImportError:
        logger.debug("Pillow no disponible — diff omitido.")
        return 0.0
    except Exception as exc:
        logger.warning("Diff de screenshot falló: %s", exc)
        return 0.0


def screenshot_to_b64(screenshot_bytes: bytes) -> str:
    """Convierte bytes PNG a string base64 para almacenar en DB."""
    return base64.b64encode(screenshot_bytes).decode("utf-8")


def b64_to_bytes(b64_str: str) -> bytes:
    """Convierte base64 de vuelta a bytes."""
    return base64.b64decode(b64_str)


def screenshot_hash(screenshot_bytes: bytes) -> str:
    """SHA-256 del screenshot para detección rápida de cambios."""
    return hashlib.sha256(screenshot_bytes).hexdigest()[:16]


def process_screenshot(url: str, previous_b64: str | None = None) -> dict | None:
    """
    Toma un screenshot, lo compara con el anterior y retorna dict listo para guardar.

    Retorna:
        {
            "image_b64":            str (base64 PNG),
            "image_hash":           str (SHA-256 truncado),
            "diff_pct":             float (0.0-100.0),
            "is_defacement_alert":  bool,
            "width":                int,
            "height":               int,
        }
    O None si no se pudo tomar el screenshot.
    """
    screenshot_bytes = take_screenshot(url)
    if not screenshot_bytes:
        return None

    image_b64   = screenshot_to_b64(screenshot_bytes)
    image_hash  = screenshot_hash(screenshot_bytes)
    diff_pct    = 0.0
    is_alert    = False

    if previous_b64:
        try:
            prev_bytes = b64_to_bytes(previous_b64)
            diff_pct   = compute_diff_pct(screenshot_bytes, prev_bytes)
            is_alert   = diff_pct >= DEFACEMENT_THRESHOLD_PCT
            if is_alert:
                logger.warning(
                    "POSIBLE DEFACEMENT detectado en %s — diff: %.1f%%", url, diff_pct
                )
        except Exception as exc:
            logger.warning("Error calculando diff: %s", exc)

    return {
        "image_b64":           image_b64,
        "image_hash":          image_hash,
        "diff_pct":            diff_pct,
        "is_defacement_alert": is_alert,
        "width":               DEFAULT_WIDTH,
        "height":              DEFAULT_HEIGHT,
    }
