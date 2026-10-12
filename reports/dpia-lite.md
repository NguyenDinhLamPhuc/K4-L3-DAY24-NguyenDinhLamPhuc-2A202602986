# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại: Hệ thống xử lý các ticket trong `corpus/`, được xem là dữ liệu đầu vào không tin cậy, cùng hồ sơ khách hàng giả trong `data/customers.json`. Ticket được phân loại là `internal`. Hồ sơ khách hàng và các trường PII được phân loại là `restricted`. PII trong nội dung ticket được phát hiện và thay thế bằng nhãn `[REDACTED_<TYPE>]` trước khi dùng cho phần tóm tắt.

2. Mục đích xử lý và principal: Mục đích là tổng hợp các ticket còn mở và truy xuất hồ sơ khách hàng liên quan khi principal có quyền.
   - `support_l1`: được phép tìm kiếm và tóm tắt ticket, nhưng không được đọc hồ sơ khách hàng restricted.
   - `dpo`: được phép đọc hồ sơ khách hàng hợp lệ cho mục đích được cấp quyền.
   - Mỗi run có `agent_id`, `run_id`, principal, scope và thời hạn. Policy kiểm tra trước khi cho phép gọi tool.

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
- Run A gọi `search_docs` để đọc ticket từ `corpus/`. Nội dung ticket được xem là untrusted content.
- Run B chỉ nhận `ticket_id` kiểu số được trích từ tên file tin cậy, sau đó ánh xạ qua `related_tickets` trong `data/customers.json` để gọi `read_customer`. 
- Mọi lần gọi tool đều đi qua `policy.check()` trước khi thực thi và được ghi vào `reports/ledger.jsonl`.
- `http_post` là sink mô phỏng tại `http://127.0.0.1:10024/*`. Policy phải chặn việc gửi dữ liệu `restricted` khi egress được bật.

4. Bằng chứng deny/allow và giới hạn của mock:
- Bằng chứng allow/deny `support_l1` bị deny khi đọc hồ sơ restricted; `dpo` được allow khi purpose, scope và thời hạn hợp lệ. Egress với dữ liệu restricted bị deny. Ledger ghi cả quyết định allow và deny, lý do, principal, run ID và hash chain
- Đây chỉ là mô phỏng học tập, không phải hồ sơ đánh giá tác động pháp lý chính thức. Principal và quyền đều là fixture giả lập, sink chỉ chạy localhost, chưa có xác thực người dùng production hoặc hệ thống quản lý secrets thực tế. PII detection dùng regex nên có thể bỏ sót hoặc phụ thuộc định dạng; test hiện ghi nhận recall khoảng 0.856. Hash chain phát hiện sửa hoặc chèn/xóa ở giữa file, nhưng không tự phát hiện việc xóa dòng cuối hoặc viết lại toàn bộ file rồi tính lại chuỗi. Các kết quả này không tự chứng minh tuân thủ pháp luật hay an toàn khi triển khai production.