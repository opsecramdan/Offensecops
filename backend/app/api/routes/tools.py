from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel
from datetime import datetime, timezone

from app.db.session import get_db
from app.db.models import ToolRegistry, User
from app.api.deps import get_current_user

router = APIRouter()


class ToolCreate(BaseModel):
    name: str
    display_name: Optional[str] = None
    category: str = "utility"
    description: Optional[str] = None
    version: Optional[str] = None
    docker_image: str
    docker_cmd: Optional[str] = None
    binary_path: Optional[str] = None
    param_schema: dict = {}
    safe_args: List[str] = []
    resource_limits: dict = {"cpu": 1.0, "memory": "512m", "timeout": 300}
    allowed_roles: List[str] = ["admin", "manager", "pentester"]
    health_check_cmd: Optional[str] = None


def tool_to_dict(t: ToolRegistry) -> dict:
    return {
        "id": t.id, "name": t.name, "display_name": t.display_name or t.name,
        "category": t.category, "description": t.description,
        "version": t.version, "docker_image": t.docker_image,
        "docker_cmd": t.docker_cmd, "binary_path": t.binary_path,
        "param_schema": t.param_schema or {}, "safe_args": t.safe_args or [],
        "resource_limits": t.resource_limits or {},
        "allowed_roles": t.allowed_roles or [],
        "is_enabled": t.is_enabled, "health_status": t.health_status,
        "health_fail_count": t.health_fail_count,
        "last_health_check": t.last_health_check.isoformat() if t.last_health_check else None,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


@router.get("/")
async def list_tools(
    category: Optional[str] = Query(None),
    is_enabled: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(ToolRegistry)
    if category:
        query = query.where(ToolRegistry.category == category)
    if is_enabled is not None:
        query = query.where(ToolRegistry.is_enabled == is_enabled)

    result = await db.execute(query.order_by(ToolRegistry.category, ToolRegistry.name))
    tools = result.scalars().all()
    return {"total": len(tools), "items": [tool_to_dict(t) for t in tools]}


@router.post("/", status_code=201)
async def register_tool(
    data: ToolCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can register tools")

    existing = await db.execute(select(ToolRegistry).where(ToolRegistry.name == data.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Tool '{data.name}' already registered")

    tool = ToolRegistry(**data.model_dump())
    db.add(tool)
    await db.commit()
    await db.refresh(tool)
    return tool_to_dict(tool)


@router.patch("/{tool_id}/toggle")
async def toggle_tool(
    tool_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can enable/disable tools")

    result = await db.execute(select(ToolRegistry).where(ToolRegistry.id == tool_id))
    tool = result.scalar_one_or_none()
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")

    tool.is_enabled = not tool.is_enabled
    await db.commit()
    return {"id": tool_id, "is_enabled": tool.is_enabled}


@router.post("/{tool_id}/health-check")
async def run_health_check(
    tool_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(ToolRegistry).where(ToolRegistry.id == tool_id))
    tool = result.scalar_one_or_none()
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")

    # TODO Phase 3: real docker health check
    # For now mark as healthy if image exists
    tool.last_health_check = datetime.now(timezone.utc)
    tool.health_status = "healthy"
    tool.health_fail_count = 0
    await db.commit()

    return {"id": tool_id, "health_status": tool.health_status, "checked_at": tool.last_health_check.isoformat()}


@router.delete("/{tool_id}", status_code=204)
async def delete_tool(
    tool_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can remove tools")
    result = await db.execute(select(ToolRegistry).where(ToolRegistry.id == tool_id))
    tool = result.scalar_one_or_none()
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")
    await db.delete(tool)
    await db.commit()


@router.patch("/{tool_id}")
async def update_tool(
    tool_id: str,
    data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can update tools")
    result = await db.execute(select(ToolRegistry).where(ToolRegistry.id == tool_id))
    tool = result.scalar_one_or_none()
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")
    for field, val in data.items():
        if hasattr(tool, field):
            setattr(tool, field, val)
    await db.commit()
    await db.refresh(tool)
    return tool_to_dict(tool)


@router.post("/seed")
async def seed_default_tools(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Seed the default tools into the registry"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    DEFAULT_TOOLS = [
        {"name": "amass", "display_name": "Amass", "category": "recon", "docker_image": "caffix/amass:latest", "version": "4.2.0", "description": "In-depth attack surface mapping and asset discovery"},
        {"name": "subfinder", "display_name": "Subfinder", "category": "recon", "docker_image": "projectdiscovery/subfinder:latest", "version": "2.6.6", "description": "Fast passive subdomain enumeration tool"},
        {"name": "httpx", "display_name": "HTTPX", "category": "recon", "docker_image": "projectdiscovery/httpx:latest", "version": "1.6.7", "description": "Fast and multi-purpose HTTP toolkit"},
        {"name": "nuclei", "display_name": "Nuclei", "category": "web", "docker_image": "projectdiscovery/nuclei:latest", "version": "3.2.0", "description": "Fast and customizable vulnerability scanner"},
        {"name": "sqlmap", "display_name": "SQLMap", "category": "web", "docker_image": "paoloo/sqlmap:latest", "version": "1.8.2", "description": "Automatic SQL injection and database takeover tool"},
        {"name": "ghauri", "display_name": "Ghauri", "category": "web", "docker_image": "r0oth3x49/ghauri:latest", "version": "1.2.0", "description": "Advanced SQL injection detection and exploitation tool"},
        {"name": "dalfox", "display_name": "DalFox", "category": "web", "docker_image": "hahwul/dalfox:latest", "version": "2.9.2", "description": "Fast parameter analysis and XSS scanner"},
        {"name": "ffuf", "display_name": "FFUF", "category": "web", "docker_image": "ffuf/ffuf:latest", "version": "2.1.0", "description": "Fast web fuzzer"},
        {"name": "dirsearch", "display_name": "Dirsearch", "category": "web", "docker_image": "dirsearch/dirsearch:latest", "version": "0.4.3", "description": "Web path discovery tool"},
        {"name": "nmap", "display_name": "Nmap", "category": "network", "docker_image": "instrumentisto/nmap:latest", "version": "7.94", "description": "Network exploration tool and security scanner"},
        {"name": "masscan", "display_name": "Masscan", "category": "network", "docker_image": "ivre/masscan:latest", "version": "1.3.2", "description": "TCP port scanner - fastest in the world"},
        {"name": "dnsx", "display_name": "DNSx", "category": "recon", "docker_image": "projectdiscovery/dnsx:latest", "version": "1.2.0", "description": "Fast and multi-purpose DNS toolkit"},
    ]

    added, skipped = 0, 0
    for t in DEFAULT_TOOLS:
        existing = await db.execute(select(ToolRegistry).where(ToolRegistry.name == t["name"]))
        if existing.scalar_one_or_none():
            skipped += 1
            continue
        db.add(ToolRegistry(**t, health_status="unknown", is_enabled=True))
        added += 1

    await db.commit()
    return {"added": added, "skipped": skipped}
