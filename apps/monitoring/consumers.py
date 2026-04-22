"""
WebSocket consumers para Continuous Monitoring.

MonitorDetailConsumer:
  - Se conecta al grupo "monitor_{target_pk}".
  - Recibe eventos de Celery worker via channel layer y los reenvía al browser.
  - Requiere autenticación + ownership del target.

DashboardConsumer:
  - Se conecta al grupo "dashboard_{user_pk}".
  - Recibe actualizaciones de TODOS los targets del usuario.
  - Permite actualización del dashboard en tiempo real.
"""
from __future__ import annotations

import json
import logging

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer

logger = logging.getLogger(__name__)


class MonitorDetailConsumer(AsyncWebsocketConsumer):
    """
    WebSocket para la página de detalle de un MonitorTarget.
    URL: ws://host/ws/monitoring/<pk>/
    """

    async def connect(self):
        user = self.scope.get("user")
        if not user or not user.is_authenticated:
            await self.close(code=4001)
            return

        self.target_pk = self.scope["url_route"]["kwargs"]["pk"]
        self.group_name = f"monitor_{self.target_pk}"

        # Verificar que el target pertenece al usuario
        target_ok = await self._check_ownership(user, self.target_pk)
        if not target_ok:
            await self.close(code=4003)
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        logger.debug(
            "WS connected: user=%s target=%s channel=%s",
            user.pk, self.target_pk, self.channel_name,
        )

    async def disconnect(self, close_code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    # Mensajes del cliente → ignorados (canal read-only para el cliente)
    async def receive(self, text_data=None, bytes_data=None):
        pass

    # ── Handlers de eventos enviados por Celery vía channel layer ────────────

    async def check_update(self, event):
        """Nuevo check completado — reenvía datos al browser."""
        await self.send(text_data=json.dumps({
            "type": "check_update",
            **event["data"],
        }))

    async def surface_update(self, event):
        """Resultados del deep check (subdomains, paths) — reenvía al browser."""
        await self.send(text_data=json.dumps({
            "type": "surface_update",
            **event["data"],
        }))

    async def screenshot_update(self, event):
        """Nuevo screenshot tomado — notifica al browser."""
        await self.send(text_data=json.dumps({
            "type": "screenshot_update",
            **event["data"],
        }))

    # ── Helpers ─────────────────────────────────────────────────────────────

    @database_sync_to_async
    def _check_ownership(self, user, target_pk: int) -> bool:
        from .models import MonitorTarget
        return MonitorTarget.objects.filter(pk=target_pk, user=user).exists()


class DashboardConsumer(AsyncWebsocketConsumer):
    """
    WebSocket para el dashboard de monitoring.
    URL: ws://host/ws/monitoring/dashboard/
    Recibe actualizaciones de todos los targets del usuario en tiempo real.
    """

    async def connect(self):
        user = self.scope.get("user")
        if not user or not user.is_authenticated:
            await self.close(code=4001)
            return

        self.user_pk = user.pk
        self.group_name = f"dashboard_{self.user_pk}"

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        logger.debug("WS dashboard connected: user=%s", self.user_pk)

    async def disconnect(self, close_code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        pass

    async def check_update(self, event):
        """Reenvía actualización de cualquier target al dashboard."""
        await self.send(text_data=json.dumps({
            "type": "check_update",
            **event["data"],
        }))
