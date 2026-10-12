"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, tools
from agent import pii
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = Path(__file__).resolve().parent.parent / "data" / "customers.json"
TICKET_ID_RE = re.compile(r"^ticket-(\d+)\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    run_id = uuid.uuid4().hex
    agent_id = f"lab24-agent/{run_id}"
    expires_at = (
        datetime.now(timezone.utc) + timedelta(minutes=15)
    ).isoformat()
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    agent_scopes = ("search_docs", "read_customer")

    def call_tool(
        tool_name: str,
        classification: str,
        args: dict,
        function=None,
        *,
        request_purpose: str = "summarize-tickets",
        egress_enabled: bool = False,
    ):
        context = PolicyContext(
            data_classification=classification,
            request_purpose=request_purpose,
            agent_owner=agent_id,
            delegation_depth=0,
            egress_enabled=egress_enabled,
            principal_id=principal_id,
            requested_tool=tool_name,
            agent_scopes=agent_scopes + ("http_post",),
            expires_at=expires_at,
        )
        allowed, reason = check(context)
        encoded_args = json.dumps(args, sort_keys=True, ensure_ascii=False).encode(
            "utf-8"
        )
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id,
            "tool": tool_name,
            "args_hash": hashlib.sha256(encoded_args).hexdigest(),
            "classification": classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        }
        ledger.append(entry, ledger_path)
        if not allowed:
            return None
        return function() if function is not None else None

    docs = call_tool(
        "search_docs",
        "internal",
        {"query": message},
        lambda: tools.search_docs(message),
    )
    docs = docs or []

    # Run B uses only ticket IDs from trusted filenames, never IDs extracted
    # from untrusted document text.
    injected = llm.find_injection(
        "\n\n".join(document["text"] for document in docs)
    )
    if injected is not None:
        call_tool(
            "http_post",
            "restricted",
            {"url": injected.target_url},
            request_purpose="support-reply",
            egress_enabled=True,
        )

    customers = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    customers_by_ticket = {
        ticket_id: customer["customer_id"]
        for customer in customers
        for ticket_id in customer.get("related_tickets", [])
    }
    ticket_ids = []
    for document in docs:
        match = TICKET_ID_RE.match(str(document.get("id", "")))
        if match:
            ticket_id = int(match.group(1))
            if ticket_id not in ticket_ids:
                ticket_ids.append(ticket_id)

    for ticket_id in ticket_ids:
        customer_id = customers_by_ticket.get(ticket_id)
        if customer_id is None:
            continue
        call_tool(
            "read_customer",
            "restricted",
            {"customer_id": customer_id},
            lambda customer_id=customer_id: tools.read_customer(customer_id),
        )

    redacted_docs = [
        {**document, "text": pii.redact(document["text"])}
        for document in docs
    ]
    return llm.summarize(redacted_docs)
