"""
WebSocket Manager
Gerencia conexões e eventos WebSocket para sincronização real-time
"""

import socketio
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Create Socket.IO server
sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins=[
        'http://localhost:5174',
        'http://localhost:5180',
        'http://localhost:3000',
        'http://127.0.0.1:5174',
        'http://127.0.0.1:5180',
        'http://127.0.0.1:3000'
    ],
    logger=True,
    engineio_logger=True
)


class WebSocketManager:
    """Gerencia conexões e broadcasts WebSocket"""

    def __init__(self):
        self.active_connections: Dict[str, set] = {}  # dashboard_id -> set of session_ids

    async def connect(self, sid: str, dashboard_id: str):
        """Registra nova conexão em um dashboard"""
        if dashboard_id not in self.active_connections:
            self.active_connections[dashboard_id] = set()

        self.active_connections[dashboard_id].add(sid)
        logger.info(f"✅ Client {sid} connected to dashboard {dashboard_id}")
        logger.info(f"📊 Dashboard {dashboard_id} now has {len(self.active_connections[dashboard_id])} connections")

    async def disconnect(self, sid: str):
        """Remove conexão de todos os dashboards"""
        for dashboard_id, connections in self.active_connections.items():
            if sid in connections:
                connections.remove(sid)
                logger.info(f"❌ Client {sid} disconnected from dashboard {dashboard_id}")
                logger.info(f"📊 Dashboard {dashboard_id} now has {len(connections)} connections")

                # Limpar dashboard se não tem mais conexões
                if len(connections) == 0:
                    del self.active_connections[dashboard_id]
                break

    async def broadcast_to_dashboard(
        self,
        dashboard_id: str,
        event: str,
        data: Dict[str, Any],
        exclude_sid: str = None
    ):
        """
        Envia evento para todos conectados em um dashboard

        Args:
            dashboard_id: ID do dashboard
            event: Nome do evento
            data: Dados do evento
            exclude_sid: Session ID para excluir (quem originou o evento)
        """
        if dashboard_id not in self.active_connections:
            logger.warning(f"⚠️ No connections for dashboard {dashboard_id}")
            return

        connections = self.active_connections[dashboard_id]

        # Enviar para todos menos quem originou
        for sid in connections:
            if sid != exclude_sid:
                try:
                    await sio.emit(event, data, room=sid)
                    logger.debug(f"📤 Sent {event} to {sid}")
                except Exception as e:
                    logger.error(f"❌ Error sending {event} to {sid}: {e}")

        logger.info(f"📡 Broadcast {event} to {len(connections) - (1 if exclude_sid else 0)} clients in dashboard {dashboard_id}")


# Singleton instance
ws_manager = WebSocketManager()


# Socket.IO Event Handlers
@sio.event
async def connect(sid, environ):
    """Cliente conectou ao WebSocket"""
    logger.info(f"🔌 New WebSocket connection: {sid}")


@sio.event
async def disconnect(sid):
    """Cliente desconectou"""
    logger.info(f"🔌 WebSocket disconnected: {sid}")
    await ws_manager.disconnect(sid)


@sio.event
async def join_dashboard(sid, data):
    """
    Cliente quer entrar em um dashboard específico

    Data: {"dashboard_id": "example-dashboard"}
    """
    dashboard_id = data.get("dashboard_id")
    if not dashboard_id:
        logger.warning(f"⚠️ Client {sid} tried to join without dashboard_id")
        return

    await ws_manager.connect(sid, dashboard_id)
    await sio.emit("joined", {"dashboard_id": dashboard_id}, room=sid)


@sio.event
async def leave_dashboard(sid, data):
    """
    Cliente quer sair de um dashboard

    Data: {"dashboard_id": "example-dashboard"}
    """
    await ws_manager.disconnect(sid)


# Funções de broadcast para usar nas APIs
async def broadcast_widget_added(dashboard_id: str, widget: Dict[str, Any], exclude_sid: str = None):
    """Notifica que um widget foi adicionado"""
    await ws_manager.broadcast_to_dashboard(
        dashboard_id=dashboard_id,
        event="widget:added",
        data={"widget": widget},
        exclude_sid=exclude_sid
    )


async def broadcast_widget_updated(dashboard_id: str, widget: Dict[str, Any], exclude_sid: str = None):
    """Notifica que um widget foi atualizado"""
    await ws_manager.broadcast_to_dashboard(
        dashboard_id=dashboard_id,
        event="widget:updated",
        data={"widget": widget},
        exclude_sid=exclude_sid
    )


async def broadcast_widget_deleted(dashboard_id: str, widget_id: str, exclude_sid: str = None):
    """Notifica que um widget foi removido"""
    await ws_manager.broadcast_to_dashboard(
        dashboard_id=dashboard_id,
        event="widget:deleted",
        data={"widget_id": widget_id},
        exclude_sid=exclude_sid
    )


async def broadcast_positions_updated(dashboard_id: str, positions: Dict[str, Any], exclude_sid: str = None):
    """Notifica que as posições dos widgets foram atualizadas"""
    await ws_manager.broadcast_to_dashboard(
        dashboard_id=dashboard_id,
        event="positions:updated",
        data={"positions": positions},
        exclude_sid=exclude_sid
    )
