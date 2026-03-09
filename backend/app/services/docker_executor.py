"""
Docker Executor — run scan tools via Docker API over Unix socket (httpx)
Bypasses docker-py http+docker scheme issue
"""
import asyncio
import httpx
import json
import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)

DOCKER_SOCKET = "/var/run/docker.sock"
SCAN_OUTPUT_DIR = "/app/scan_outputs"

DEFAULT_LIMITS = {
    "cpu_quota": 100000,
    "mem_limit": 536870912,   # 512MB in bytes
    "pids_limit": 100,
}

TOOL_IMAGES = {
    "nmap":      "instrumentisto/nmap:latest",
    "nuclei":    "projectdiscovery/nuclei:latest",
    "httpx":     "projectdiscovery/httpx:latest",
    "subfinder": "projectdiscovery/subfinder:latest",
    "dnsx":      "projectdiscovery/dnsx:latest",
    "testssl":   "drwetter/testssl.sh:latest",
    "masscan":   "isontheline/masscan:latest",
}

os.makedirs(SCAN_OUTPUT_DIR, exist_ok=True)


def _get_sync_transport():
    return httpx.HTTPTransport(uds=DOCKER_SOCKET)


def _get_async_transport():
    return httpx.AsyncHTTPTransport(uds=DOCKER_SOCKET)


def get_docker_client():
    """Return sync httpx client connected to Docker socket"""
    return httpx.Client(
        transport=_get_sync_transport(),
        base_url="http://docker",
        timeout=30,
    )


async def pull_image_if_needed(image: str) -> bool:
    """Pull Docker image if not present"""
    async with httpx.AsyncClient(
        transport=_get_async_transport(),
        base_url="http://docker",
        timeout=120,
    ) as client:
        # Check if image exists
        try:
            r = await client.get(f"/images/{image.replace(':', '%3A')}/json")
            if r.status_code == 200:
                return True
        except Exception:
            pass

        # Pull image
        logger.info(f"Pulling image: {image}")
        try:
            repo, tag = image.rsplit(':', 1) if ':' in image else (image, 'latest')
            r = await client.post(
                "/images/create",
                params={"fromImage": repo, "tag": tag},
                timeout=300,
            )
            return r.status_code == 200
        except Exception as e:
            logger.error(f"Pull failed for {image}: {e}")
            return False


async def run_container(
    image: str,
    cmd: list,
    timeout: int = 300,
    mem_limit: str = "512m",
    cpu_quota: int = 100000,
    network_mode: str = "bridge",
    volumes: Optional[dict] = None,
    environment: Optional[dict] = None,
) -> tuple[int, str, str]:
    """
    Run a container and return (exit_code, stdout, stderr)
    Uses Docker API directly via Unix socket with httpx
    """
    # Convert mem_limit string to bytes
    mem_bytes = DEFAULT_LIMITS["mem_limit"]
    if isinstance(mem_limit, str):
        if mem_limit.endswith('m'):
            mem_bytes = int(mem_limit[:-1]) * 1024 * 1024
        elif mem_limit.endswith('g'):
            mem_bytes = int(mem_limit[:-1]) * 1024 * 1024 * 1024
        else:
            mem_bytes = int(mem_limit)

    # Build container config
    config = {
        "Image": image,
        "Cmd": cmd,
        "AttachStdout": True,
        "AttachStderr": True,
        "NetworkDisabled": False,
        "HostConfig": {
            "Memory": mem_bytes,
            "MemorySwap": mem_bytes,
            "CpuQuota": cpu_quota,
            "PidsLimit": DEFAULT_LIMITS["pids_limit"],
            "NetworkMode": network_mode,
            "AutoRemove": False,
            "SecurityOpt": ["no-new-privileges"],
        },
    }

    if volumes:
        binds = []
        volume_map = {}
        for host_path, container_path in volumes.items():
            mode = "rw"
            if isinstance(container_path, dict):
                mode = container_path.get("mode", "rw")
                container_path = container_path["bind"]
            binds.append(f"{host_path}:{container_path}:{mode}")
            volume_map[container_path] = {}
        config["Volumes"] = volume_map
        config["HostConfig"]["Binds"] = binds

    if environment:
        config["Env"] = [f"{k}={v}" for k, v in environment.items()]

    async with httpx.AsyncClient(
        transport=_get_async_transport(),
        base_url="http://docker",
        timeout=timeout + 30,
    ) as client:
        container_id = None
        try:
            # Create container
            r = await client.post(
                "/containers/create",
                json=config,
                headers={"Content-Type": "application/json"},
            )
            if r.status_code not in (200, 201):
                logger.error(f"Container create failed: {r.status_code} {r.text[:200]}")
                return -1, "", r.text[:200]

            container_id = r.json()["Id"]
            logger.debug(f"Container created: {container_id[:12]}")

            # Start container
            r = await client.post(f"/containers/{container_id}/start")
            if r.status_code not in (200, 204):
                logger.error(f"Container start failed: {r.status_code}")
                return -1, "", f"Start failed: {r.status_code}"

            # Wait for container with timeout
            r = await client.post(
                f"/containers/{container_id}/wait",
                params={"condition": "not-running"},
                timeout=timeout + 10,
            )
            exit_code = 0
            if r.status_code == 200:
                exit_code = r.json().get("StatusCode", 0)

            # Get logs
            r = await client.get(
                f"/containers/{container_id}/logs",
                params={"stdout": "true", "stderr": "true"},
            )
            raw = r.content

            # Docker log format: 8-byte header per chunk
            stdout_lines = []
            stderr_lines = []
            i = 0
            while i < len(raw):
                if i + 8 > len(raw):
                    break
                stream_type = raw[i]
                length = int.from_bytes(raw[i+4:i+8], 'big')
                data = raw[i+8:i+8+length].decode('utf-8', errors='replace')
                if stream_type == 1:
                    stdout_lines.append(data)
                else:
                    stderr_lines.append(data)
                i += 8 + length

            stdout = ''.join(stdout_lines)
            stderr = ''.join(stderr_lines)

            logger.debug(f"Container {container_id[:12]} exit={exit_code} "
                        f"stdout={len(stdout)}b stderr={len(stderr)}b")
            return exit_code, stdout, stderr

        except httpx.TimeoutException:
            logger.error(f"Container timeout after {timeout}s")
            return -1, "", f"Timeout after {timeout}s"
        except Exception as e:
            logger.error(f"Container error: {e}")
            return -1, "", str(e)
        finally:
            # Cleanup container
            if container_id:
                try:
                    async with httpx.AsyncClient(
                        transport=_get_async_transport(),
                        base_url="http://docker",
                        timeout=10,
                    ) as cleanup:
                        await cleanup.delete(
                            f"/containers/{container_id}",
                            params={"force": "true"},
                        )
                except Exception:
                    pass
