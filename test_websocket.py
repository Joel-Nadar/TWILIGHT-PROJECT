"""
Quick WebSocket test client.
"""
import asyncio
import websockets
import json


async def test_websocket():
    uri = "ws://127.0.0.1:8000/ws"
    async with websockets.connect(uri) as websocket:
        print("Connected to WebSocket")
        
        # Wait for a message
        try:
            message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
            print(f"Received: {message}")
            data = json.loads(message)
            print(f"Type: {data.get('type')}")
            print(f"Data: {data.get('data')}")
        except asyncio.TimeoutError:
            print("No message received within timeout (normal if no events sent)")


if __name__ == "__main__":
    asyncio.run(test_websocket())
