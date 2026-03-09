"""
Redis Pub/Sub untuk real-time streaming output scan ke WebSocket
"""
import redis.asyncio as aioredis
import json
import os

REDIS_URL = os.getenv("REDIS_URL", "redis://:changeme@redis:6379/0")

def get_redis():
    return aioredis.from_url(REDIS_URL, decode_responses=True)

def scan_channel(scan_job_id: str) -> str:
    return f"scan:output:{scan_job_id}"

async def publish_line(scan_job_id: str, data: dict):
    """Publish satu baris output ke Redis channel"""
    r = get_redis()
    try:
        await r.publish(scan_channel(scan_job_id), json.dumps(data))
    finally:
        await r.aclose()

async def subscribe_scan(scan_job_id: str):
    """Generator async: yield setiap message dari channel scan"""
    r = get_redis()
    pubsub = r.pubsub()
    await pubsub.subscribe(scan_channel(scan_job_id))
    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                yield json.loads(message["data"])
    finally:
        await pubsub.unsubscribe()
        await r.aclose()
