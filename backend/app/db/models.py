from sqlalchemy import Column, String, Boolean, Integer, Float, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.db.session import Base


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    full_name = Column(String(255))
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="pentester")
    is_active = Column(Boolean, default=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class UserSession(Base):
    __tablename__ = "user_sessions"
    id = Column(String, primary_key=True, default=lambda: __import__('uuid').uuid4().hex)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    refresh_token_hash = Column(String(255), unique=True, nullable=False)
    ip_address = Column(String(50))
    user_agent = Column(Text)
    is_revoked = Column(Boolean, default=False)
    expires_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Target(Base):
    __tablename__ = "targets"
    id = Column(String, primary_key=True)
    value = Column(String(512), nullable=False)
    type = Column(String(50), default="domain")
    owner = Column(String(255))
    criticality = Column(String(50), default="medium")
    tags = Column(JSON, default=list)
    notes = Column(Text)
    scope_status = Column(String(50), default="in_scope")
    created_by = Column(String, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id = Column(String, primary_key=True)
    target_value = Column(String(512))
    target_id = Column(String, ForeignKey("targets.id"), nullable=True)
    mode = Column(String(50), default="quick")
    status = Column(String(50), default="pending")
    tool_ids = Column(JSON, default=list)
    parameters = Column(JSON, default=dict)
    raw_output = Column(Text)
    error = Column(Text)
    created_by = Column(String, ForeignKey("users.id"))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(String, primary_key=True)
    title = Column(String(512), nullable=False)
    description = Column(Text)
    cvss_score = Column(Float)
    severity = Column(String(50), default="medium")
    cve_ids = Column(JSON, default=list)
    cwe_ids = Column(JSON, default=list)
    affected_asset = Column(String(512))
    target_id = Column(String, ForeignKey("targets.id"), nullable=True)
    scan_id = Column(String, ForeignKey("scan_jobs.id"), nullable=True)
    status = Column(String(50), default="open")
    is_false_positive = Column(Boolean, default=False)
    fp_reason = Column(Text)
    remediation_notes = Column(Text)
    evidence = Column(Text)
    assigned_to = Column(String, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ToolRegistry(Base):
    __tablename__ = "tool_registry"
    id = Column(String, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    display_name = Column(String(255))
    category = Column(String(50))
    description = Column(Text)
    docker_image = Column(String(512))
    binary_path = Column(String(512))
    safe_args = Column(JSON, default=list)
    param_schema = Column(JSON, default=dict)
    resource_limits = Column(JSON, default=dict)
    allowed_roles = Column(JSON, default=list)
    is_enabled = Column(Boolean, default=True)
    health_status = Column(String(50), default="unknown")
    last_health_check = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class SQLiSession(Base):
    __tablename__ = "sqli_sessions"
    id = Column(String, primary_key=True)
    name = Column(String(255))
    config = Column(JSON, default=dict)
    status = Column(String(50), default="saved")
    output = Column(Text)
    created_by = Column(String, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=lambda: __import__('uuid').uuid4().hex)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action = Column(String(255))
    resource_type = Column(String(100))
    resource_id = Column(String(255))
    ip_address = Column(String(50))
    user_agent = Column(Text)
    request_payload = Column(JSON)
    response_code = Column(Integer)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Report(Base):
    __tablename__ = "reports"
    id = Column(String, primary_key=True)
    title = Column(String(512))
    type = Column(String(50), default="technical")
    status = Column(String(50), default="pending")
    file_path = Column(String(512))
    created_by = Column(String, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# Required for init_db import
all_models = [User, UserSession, Target, ScanJob, Vulnerability, ToolRegistry, SQLiSession, AuditLog, Report]


# ── Vulnerability Management (Multi-Company) ──────────────────
class VulnCompany(Base):
    __tablename__ = "vuln_companies"
    id = Column(String, primary_key=True)
    name = Column(String(255), nullable=False)
    code = Column(String(50), nullable=False, unique=True)  # e.g. SPRINT, BAYARIND
    color = Column(String(20), default="#6366f1")
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    reports = relationship("VulnReport", back_populates="company", cascade="all, delete-orphan")

class VulnStatus(Base):
    __tablename__ = "vuln_statuses"
    id = Column(String, primary_key=True)
    name = Column(String(100), nullable=False)
    color = Column(String(20), default="#74c7ec")
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class VulnReport(Base):
    __tablename__ = "vuln_reports"
    id = Column(String, primary_key=True)
    company_id = Column(String, ForeignKey("vuln_companies.id"), nullable=False)
    # Identifiers
    no = Column(Integer)
    vuln_code = Column(String(100))       # e.g. SP-A05
    vuln_id = Column(String(100))         # e.g. SP-A05-01
    vuln_members = Column(String(512))
    # Core fields
    vuln_name = Column(String(512), nullable=False)
    description = Column(Text)
    severity = Column(String(50), default="medium")
    cvss_vector = Column(String(512))
    cvss_score = Column(Float)
    cvss_version = Column(String(10), default="3.1")  # 3.1 or 4.0
    impact = Column(Text)
    mitigation = Column(Text)
    status = Column(String(100), default="Open")
    # Dates
    finding_date = Column(DateTime(timezone=True))
    resolution_date = Column(DateTime(timezone=True))
    fixing_date = Column(DateTime(timezone=True))
    # Extra
    referensi = Column(Text)
    note = Column(Text)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    company = relationship("VulnCompany", back_populates="reports")
