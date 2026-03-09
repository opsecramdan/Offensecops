import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Text, Boolean, Integer, Float, DateTime,
    ForeignKey, Enum, JSON, ARRAY, func
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.db.session import Base


def gen_uuid():
    return str(uuid.uuid4())


# ─── USERS ──────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(256), unique=True, nullable=False)
    full_name = Column(String(256))
    hashed_password = Column(String(256), nullable=False)
    role = Column(Enum("admin", "manager", "pentester", "viewer", "auditor", name="user_role"), nullable=False, default="pentester")
    is_active = Column(Boolean, default=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class UserSession(Base):
    __tablename__ = "user_sessions"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    refresh_token_hash = Column(String(256), unique=True, nullable=False)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    is_revoked = Column(Boolean, default=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ─── TARGETS ────────────────────────────────────────────────────────────────
# ─── TARGET GROUPS ──────────────────────────────────────────────────────────
class TargetGroup(Base):
    __tablename__ = "target_groups"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    name = Column(String(128), unique=True, nullable=False)
    description = Column(Text)
    color = Column(String(16), default="#6366f1")
    created_by = Column(String(36))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    targets = relationship("Target", back_populates="group")


class Target(Base):
    __tablename__ = "targets"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    value = Column(String(512), nullable=False)
    type = Column(Enum("domain", "subdomain", "ip", "cidr", "url", name="target_type"), nullable=False)
    ip_address = Column(String(45))
    owner = Column(String(256))
    criticality = Column(Enum("critical", "high", "medium", "low", "informational", name="criticality_level"), default="medium")
    tags = Column(ARRAY(String), default=[])
    notes = Column(Text)
    scope_status = Column(Enum("in_scope", "out_of_scope", "pending", name="scope_status"), default="pending")
    group_id = Column(String(36), ForeignKey("target_groups.id"), nullable=True)
    created_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    group = relationship("TargetGroup", back_populates="targets")


# ─── TOOL REGISTRY ──────────────────────────────────────────────────────────
class ToolRegistry(Base):
    __tablename__ = "tool_registry"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    name = Column(String(64), unique=True, nullable=False)
    display_name = Column(String(128))
    category = Column(Enum("recon", "network", "web", "exploit", "utility", name="tool_category"))
    description = Column(Text)
    version = Column(String(32))
    docker_image = Column(String(256), nullable=False)
    docker_cmd = Column(String(512))
    binary_path = Column(String(256))
    param_schema = Column(JSON, default={})
    safe_args = Column(ARRAY(String), default=[])
    resource_limits = Column(JSON, default={"cpu": 1.0, "memory": "512m", "timeout": 300})
    allowed_roles = Column(ARRAY(String), default=["admin", "manager", "pentester"])
    is_enabled = Column(Boolean, default=True)
    health_check_cmd = Column(String(256))
    health_status = Column(Enum("healthy", "degraded", "offline", "unknown", name="health_status"), default="unknown")
    last_health_check = Column(DateTime(timezone=True))
    health_fail_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


# ─── SCAN JOBS ──────────────────────────────────────────────────────────────
class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    celery_task_id = Column(String(256))
    target_id = Column(UUID(as_uuid=False), ForeignKey("targets.id"))
    target_value = Column(String(512), nullable=False)
    scan_mode = Column(Enum("quick", "full", "custom", name="scan_mode"), default="custom")
    status = Column(Enum("queued", "running", "completed", "failed", "cancelled", name="job_status"), default="queued")
    progress = Column(Integer, default=0)
    tools = Column(ARRAY(String), default=[])
    parameters = Column(JSON, default={})
    raw_output = Column(Text)
    error_message = Column(Text)
    created_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    # Scan engine fields
    target = Column(String(512))
    modules = Column(ARRAY(String), default=[])
    options = Column(JSON, default={})
    result_summary = Column(JSON, default={})
    risk_score = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    finished_at = Column(DateTime(timezone=True))


# ─── VULNERABILITIES ────────────────────────────────────────────────────────
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    title = Column(String(512), nullable=False)
    description = Column(Text)
    cvss_score = Column(Float)
    cvss_vector = Column(String(256))
    severity = Column(Enum("critical", "high", "medium", "low", "informational", name="vuln_severity"))
    cve_ids = Column(ARRAY(String), default=[])
    cwe_ids = Column(ARRAY(String), default=[])
    mitre_techniques = Column(ARRAY(String), default=[])
    affected_asset = Column(String(512))
    scan_job_id = Column(UUID(as_uuid=False), ForeignKey("scan_jobs.id"))
    status = Column(Enum("open", "in_remediation", "false_positive", "resolved", name="vuln_status"), default="open")
    is_false_positive = Column(Boolean, default=False)
    fp_reason = Column(Text)
    fp_marked_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    sla_due_date = Column(DateTime(timezone=True))
    sla_breached = Column(Boolean, default=False)
    remediation_notes = Column(Text)
    assigned_to = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    resolved_at = Column(DateTime(timezone=True))
    evidence = Column(JSON, default={})
    references = Column(ARRAY(String), default=[])
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


# ─── AUDIT LOGS ─────────────────────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    username = Column(String(64))
    action = Column(String(128), nullable=False, index=True)
    resource_type = Column(String(64))
    resource_id = Column(String(256))
    ip_address = Column(String(45))
    user_agent = Column(Text)
    request_payload = Column(JSON)
    response_code = Column(Integer)
    ts = Column(DateTime(timezone=True), server_default=func.now(), index=True)


# ─── SQLI SESSIONS ──────────────────────────────────────────────────────────
class SQLiSession(Base):
    __tablename__ = "sqli_sessions"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    name = Column(String(256))
    target_url = Column(String(2048), nullable=False)
    tool = Column(Enum("sqlmap", "ghauri", name="sqli_tool"), default="sqlmap")
    http_method = Column(String(10), default="GET")
    post_data = Column(Text)
    cookie_string = Column(Text)
    headers = Column(JSON, default={})
    injection_param = Column(String(256))
    risk_level = Column(Integer, default=1)
    level_depth = Column(Integer, default=1)
    techniques = Column(ARRAY(String), default=["B", "E"])
    tamper_scripts = Column(ARRAY(String), default=[])
    dbms = Column(String(64), default="auto")
    threads = Column(Integer, default=4)
    time_delay = Column(Integer, default=5)
    proxy = Column(String(512))
    extra_options = Column(JSON, default={})
    scan_job_id = Column(UUID(as_uuid=False), ForeignKey("scan_jobs.id"))
    created_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


# ─── REPORTS ────────────────────────────────────────────────────────────────
class Report(Base):
    __tablename__ = "reports"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    title = Column(String(512), nullable=False)
    report_type = Column(Enum("technical", "executive", name="report_type"), default="technical")
    file_path = Column(String(1024))
    file_size = Column(Integer)
    target_ids = Column(ARRAY(String), default=[])
    scan_job_ids = Column(ARRAY(String), default=[])
    generated_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# Register all models
all_models = [User, UserSession, Target, TargetGroup, ToolRegistry, ScanJob, Vulnerability, AuditLog, SQLiSession, Report]



# ─── SCAN ENGINE ────────────────────────────────────────────────────────────
class ScanFinding(Base):
    __tablename__ = "scan_findings"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_job_id = Column(UUID(as_uuid=False), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    target_value = Column(String(512), nullable=False)
    module = Column(String(64), nullable=False)
    severity = Column(String(16), default="info")
    title = Column(String(256), nullable=False)
    description = Column(Text)
    evidence = Column(Text)
    host = Column(String(256))
    port = Column(Integer)
    protocol = Column(String(16))
    service = Column(String(64))
    cve_ids = Column(ARRAY(String), default=[])
    cvss_score = Column(Float)
    cpe = Column(String(256))
    remediation = Column(Text)
    owasp_category = Column(String(64))
    false_positive = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class CVECache(Base):
    __tablename__ = "cve_cache"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    cve_id = Column(String(32), unique=True, nullable=False, index=True)
    description = Column(Text)
    cvss_v3_score = Column(Float)
    cvss_v2_score = Column(Float)
    severity = Column(String(16))
    cpe_matches = Column(ARRAY(String), default=[])
    published = Column(DateTime(timezone=True))
    modified = Column(DateTime(timezone=True))
    is_kev = Column(Boolean, default=False)
    kev_date = Column(DateTime(timezone=True))
    references = Column(ARRAY(String), default=[])
    raw_data = Column(JSON, default={})
    cached_at = Column(DateTime(timezone=True), server_default=func.now())


class NVDIngestionLog(Base):
    __tablename__ = "nvd_ingestion_log"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    feed_year = Column(Integer)
    status = Column(String(16), default="pending")
    cve_count = Column(Integer, default=0)
    error_msg = Column(Text)
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


all_models = [User, UserSession, Target, TargetGroup, ToolRegistry, ScanJob, Vulnerability, AuditLog, SQLiSession, Report, ScanFinding, CVECache, NVDIngestionLog]


# ── Vulnerability Management (Multi-Company) ──────────────────
class VulnCompany(Base):
    __tablename__ = "vuln_companies"
    id = Column(String, primary_key=True)
    name = Column(String(255), nullable=False)
    code = Column(String(50), nullable=False, unique=True)
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
    no = Column(Integer)
    vuln_code = Column(String(100))
    vuln_id = Column(String(100))
    vuln_members = Column(String(512))
    vuln_name = Column(String(512), nullable=False)
    description = Column(Text)
    severity = Column(String(50), default="medium")
    cvss_vector = Column(String(512))
    cvss_score = Column(Float)
    cvss_version = Column(String(10), default="3.1")
    impact = Column(Text)
    mitigation = Column(Text)
    status = Column(String(100), default="Open")
    finding_date = Column(DateTime(timezone=True))
    resolution_date = Column(DateTime(timezone=True))
    fixing_date = Column(DateTime(timezone=True))
    referensi = Column(Text)
    note = Column(Text)
    product_id = Column(String, ForeignKey("vuln_products.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    company = relationship("VulnCompany", back_populates="reports")


# ── Vuln Products ─────────────────────────────────────────────
class VulnProduct(Base):
    __tablename__ = "vuln_products"
    id = Column(String, primary_key=True)
    company_id = Column(String, ForeignKey("vuln_companies.id"), nullable=False)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# ── POC Reports ───────────────────────────────────────────────
class PocReport(Base):
    __tablename__ = "poc_reports"
    id = Column(String, primary_key=True)
    vuln_report_id = Column(String, ForeignKey("vuln_reports.id"), nullable=False)
    # Auto-filled
    vuln_id = Column(String(100))
    vuln_name = Column(String(512))
    cvss_vector = Column(String(512))
    cvss_score = Column(Float)
    severity = Column(String(50))
    # Manual fields
    status = Column(String(50), default="BELUM DIPERBAIKI")  # DIPERBAIKI / BELUM DIPERBAIKI
    description = Column(Text)
    poc_steps = Column(Text)
    reference = Column(Text)
    recommendation = Column(Text)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    evidences = relationship("PocEvidence", back_populates="poc", cascade="all, delete-orphan", order_by="PocEvidence.order_no")
    retestings = relationship("PocRetesting", back_populates="poc", cascade="all, delete-orphan", order_by="PocRetesting.created_at")

class PocEvidence(Base):
    __tablename__ = "poc_evidences"
    id = Column(String, primary_key=True)
    poc_id = Column(String, ForeignKey("poc_reports.id"), nullable=False)
    order_no = Column(Integer, default=1)
    label = Column(String(100), default="Evidence-01")
    caption = Column(Text)
    file_path = Column(String(512))
    file_name = Column(String(255))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    poc = relationship("PocReport", back_populates="evidences")

class PocRetesting(Base):
    __tablename__ = "poc_retestings"
    id = Column(String, primary_key=True)
    poc_id = Column(String, ForeignKey("poc_reports.id"), nullable=False)
    retest_date = Column(DateTime(timezone=True))
    result = Column(Text)
    status = Column(String(50), default="BELUM DIPERBAIKI")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    evidences = relationship("PocRetestEvidence", back_populates="retest", cascade="all, delete-orphan")
    poc = relationship("PocReport", back_populates="retestings")

class PocRetestEvidence(Base):
    __tablename__ = "poc_retest_evidences"
    id = Column(String, primary_key=True)
    retest_id = Column(String, ForeignKey("poc_retestings.id"), nullable=False)
    order_no = Column(Integer, default=1)
    label = Column(String(100))
    caption = Column(Text)
    file_path = Column(String(512))
    file_name = Column(String(255))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    retest = relationship("PocRetesting", back_populates="evidences")
