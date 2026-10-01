"""
WebSocket connection manager for Twilight Gateway.
Publishes decisions, incidents, trust changes, and status changes.
"""
from typing import Dict, Set
from fastapi import WebSocket
from datetime import datetime
import json


class ConnectionManager:
    """Manages WebSocket connections and broadcasts messages"""
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
    
    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection"""
        await websocket.accept()
        self.active_connections.add(websocket)
    
    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection"""
        self.active_connections.discard(websocket)
    
    async def publish(self, message_type: str, data: dict):
        """
        Publish a message to all connected clients.
        Message envelope: {"type": "...", "ts": "...", "data": {...}}
        Data must be redacted before calling this.
        """
        message = {
            "type": message_type,
            "ts": datetime.utcnow().isoformat() + "Z",
            "data": data
        }
        
        # Send to all connected clients
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.add(connection)
        
        # Clean up disconnected clients
        for connection in disconnected:
            self.disconnect(connection)


# Global connection manager
manager = ConnectionManager()
