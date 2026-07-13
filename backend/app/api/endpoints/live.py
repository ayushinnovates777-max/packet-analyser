from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import pyshark
import asyncio
import json
import time
import random

router = APIRouter()

@router.websocket("/ws")
async def live_capture_ws(websocket: WebSocket):
    await websocket.accept()
    
    try:
        # Attempt real live capture
        # pyshark's sniff_continuously is a blocking generator in some versions.
        # We run it in a thread executor to avoid blocking the FastAPI event loop
        # and to avoid the __aiter__ exception.
        cap = pyshark.LiveCapture()
        iterator = cap.sniff_continuously()
        
        while True:
            # Yield control back to event loop, fetching the next packet in a background thread
            packet = await asyncio.get_event_loop().run_in_executor(None, next, iterator)
            
            try:
                src_ip = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
                dst_ip = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
                protocol = packet.highest_layer
                length = packet.length
                
                data = {
                    "type": "packet",
                    "timestamp": time.time(),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "length": length,
                    "summary": str(packet)
                }
                await websocket.send_text(json.dumps(data))
            except Exception:
                pass
                
    except WebSocketDisconnect:
        print("Client disconnected from Live Capture")
    except Exception as e:
        print(f"Live sniffing not available (needs Admin/Npcap): {e}. Falling back to simulation.")
        # Fallback to simulated "Matrix-style" data if no permissions/Npcap
        try:
            protos = ["TCP", "UDP", "TLSv1.2", "TLSv1.3", "HTTP", "DNS", "ICMP", "ARP"]
            while True:
                mock_protocol = random.choice(protos)
                src = f"192.168.1.{random.randint(1, 254)}"
                dst = f"{random.randint(8, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                
                data = {
                    "type": "packet",
                    "timestamp": time.time(),
                    "src_ip": src,
                    "dst_ip": dst,
                    "protocol": mock_protocol,
                    "length": random.randint(40, 1500),
                    "summary": f"Simulated Frame Data\nSource: {src}\nDestination: {dst}\nProtocol: {mock_protocol}\nInfo: Standard network chatter sequence simulated for UI testing."
                }
                await websocket.send_text(json.dumps(data))
                # Random bursty delay
                await asyncio.sleep(random.uniform(0.01, 0.3))
        except WebSocketDisconnect:
            print("Client disconnected from Simulation")
