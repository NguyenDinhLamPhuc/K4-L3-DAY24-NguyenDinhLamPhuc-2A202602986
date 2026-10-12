"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def check(context: PolicyContext) -> tuple[bool, str]:
    allowed_classifications = {"public", "internal", "restricted"}
    if context.data_classification not in allowed_classifications:
        return False, "data_classification không hợp lệ"

    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "restricted data không được phép egress"

    if not context.agent_owner.strip():
        return False, "agent_owner bị thiếu"
    if context.delegation_depth < 0:
        return False, "delegation_depth không hợp lệ"
    if not context.principal_id.strip():
        return False, "principal_id bị thiếu"
    if not context.request_purpose.strip():
        return False, "request_purpose bị thiếu"
    if not context.requested_tool.strip():
        return False, "requested_tool bị thiếu"
    if not context.agent_scopes:
        return False, "agent_scopes bị thiếu"
    if context.delegation_depth > 0 and not context.parent_scopes:
        return False, "parent_scopes bị thiếu khi delegation"

    principals_path = Path(__file__).resolve().parent.parent / "data" / "principals.json"
    try:
        principals = json.loads(principals_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, "không thể đọc danh sách principal"

    principal = principals.get(context.principal_id)
    if not isinstance(principal, dict):
        return False, "principal không xác định"

    allowed_tools = principal.get("allowed_tools")
    purposes = principal.get("purposes")
    if not isinstance(allowed_tools, list) or not isinstance(purposes, list):
        return False, "principal thiếu policy quyền hạn"
    if context.request_purpose not in purposes:
        return False, "purpose không được principal cho phép"

    effective_scopes = set(allowed_tools).intersection(context.agent_scopes)
    if context.delegation_depth > 0:
        effective_scopes.intersection_update(context.parent_scopes)
    if context.requested_tool not in effective_scopes:
        return False, "requested_tool nằm ngoài phạm vi quyền hiệu lực"

    try:
        expires_at = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return False, "expires_at không hợp lệ"
    if expires_at.tzinfo is None:
        return False, "expires_at phải có timezone UTC"
    if expires_at.astimezone(timezone.utc) <= datetime.now(timezone.utc):
        return False, "run đã hết hạn"

    return True, "policy hợp lệ: principal, purpose, tool, scope và thời hạn đều được phép"
