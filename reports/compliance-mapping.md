# Compliance mapping — điền trong checkpoint 5

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| Luật 91/2025/QH15 | Phát hiện và redact PII trước khi đưa nội dung vào context; phân loại restricted; chặn egress với dữ liệu restricted; kiểm soát principal và mục đích truy cập. | pii.py:55, pii.py:80, policy.py:57, runner.py:83 | Chưa đối chiếu văn bản gốc hoặc điều khoản cụ thể; đây chỉ là mô phỏng kỹ thuật, không chứng minh tuân thủ luật. |
| NĐ 356/2025/NĐ-CP | Có policy enforcement trước mỗi tool call, deny khi thiếu quyền hoặc hết hạn, và ledger ghi cả quyết định allow/deny cùng lý do. | policy.py:57, runner.py:94, ledger.py:45 | Chưa đối chiếu văn bản gốc; chưa chứng minh đầy đủ các yêu cầu vận hành, thông báo, lưu trữ hoặc đánh giá tác động theo quy định. |
| Luật AI 134/2025/QH15 | Tách xử lý nội dung không tin cậy khỏi việc đọc dữ liệu riêng tư; giới hạn tool theo principal, scope, purpose và thời hạn; ghi audit trail. | runner.py:142, policy.py:57, ledger.py:45 | Chưa đối chiếu văn bản gốc hoặc điều khoản cụ thể; mock không thay thế đánh giá rủi ro, giám sát con người hay kiểm định hệ thống AI thực tế. |
| OWASP ASI01, ASI03, ASI04 | ASI01: containment prompt injection bằng typed ticket ID và split giữa các run. ASI03: kiểm soát identity, principal, scope, delegation và expiration tại PEP. ASI04: pin Gitleaks, lock dependency bằng hash và ghi nhận secret synthetic trong lịch sử Git. | runner.py:142, policy.py:57, ledger.py:45, .gitleaks.toml:7, test_supply_chain.py:12 | Đây là mapping kỹ thuật theo bài lab. Token trong bài là synthetic, không chứng minh quy trình xử lý credential thật. |

Chỉ ghi điều khoản cụ thể khi đã đối chiếu văn bản gốc. Mô phỏng kỹ thuật không tự chứng minh tuân thủ pháp luật.
