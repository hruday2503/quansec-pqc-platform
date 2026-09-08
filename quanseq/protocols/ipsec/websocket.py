"""
websocket.py — real-time WebSocket endpoint for QUANSEQ dashboard.

Clients connect to /api/ws/live and receive a live JSON stream of:
  - IPsec tunnel state changes (every 5s from collector)
  - Lifecycle events (ESTABLISHED, CHILD_UP, DOWN) as they happen
  - Traffic counter updates

The collector and event listener both publish to Redis channel
'quanseq:live'. This endpoint subscribes and forwards to all
connected WebSocket clients.
"""

import asyncio
import json
import logging

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.config import settings

logger = logging.getLogger("quanseq.ipsec.websocket")
router = APIRouter()

# Track connected clients
connected_clients: list[WebSocket] = []


@router.websocket("/api/ws/live")
async def websocket_live(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    client = websocket.client
    logger.info(f"WebSocket client connected: {client}")

    try:
        redis = aioredis.from_url(
            settings.REDIS_URL, encoding="utf-8", decode_responses=True
        )
        pubsub = redis.pubsub()
        await pubsub.subscribe("quanseq:live")

        # Send immediate status on connect
        await websocket.send_json({
            "type": "connected",
            "message": "QUANSEQ live feed connected",
            "channel": "quanseq:live"
        })

        # Listen for messages from Redis and forward to client
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    await websocket.send_json(data)
                except Exception as e:
                    logger.error(f"WebSocket send error: {e}")
                    break

    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected: {client}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        connected_clients.remove(websocket)
        try:
            await pubsub.unsubscribe("quanseq:live")
            await redis.close()
        except Exception:
            pass
