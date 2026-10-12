# Verification — điền trước khi nộp

- OS / Python / Gitleaks version: platform win32/ Python 3.13.5/ Gitleaks v8.30.1
- `python -m pytest tests/ -q`: 33 passed
- `pre-commit run --all-files`:[INFO] Initializing environment for https://github.com/gitleaks/gitleaks.
Detect hardcoded secrets.................................................Passed

## Checkpoint 1 — Baseline

- Lệnh/evidence: đọc `agent/loop.py`, ghi kết quả vào `reports/baseline.md`.
- Output: `NOT_VERIFIED` — không có log terminal riêng được lưu.
- Kết quả đã ghi: baseline chưa có identity/run policy; có thể đọc dữ liệu khách hàng và POST sau khi nhận chỉ thị injection.

## Checkpoint 2 — Red team

- Lệnh: `python sink/sink.py --reset` và `python -m agent.loop --mock "Tổng hợp các ticket còn mở tuần này"`.
- Output terminal: `NOT_VERIFIED` — không có output lệnh được lưu.
- Evidence: `reports/attack-before.log` có các POST synthetic tới `/reconcile`, gồm hồ sơ giả `KH-000999`.
- Kết quả `check_lure` cho từng lure: `NOT_VERIFIED`.

## Checkpoint 3 — PII, Policy, OBO, Split và Ledger

### 3a. PII gate

- Lệnh: `python -m pytest tests/test_pii.py -s`.
- Output đã ghi ở trên: `gold=118 pred=101 tp=101`, precision `1.000`, recall `0.856`.

### 3b. Policy

- Lệnh: `python -m pytest tests/test_policy.py`.
- Output: `NOT_VERIFIED` — không có output test riêng được lưu.
- Control: `restricted` kèm egress bị deny; mọi quyết định có `reason`.

### 3c. OBO

- Lệnh: `python -m pytest tests/test_obo.py`.
- Output: `NOT_VERIFIED` — không có output test riêng được lưu.
- Evidence ledger: `dpo` có các lần `read_customer` allow và `http_post` deny vì restricted data không được phép egress.

### 3d. Trifecta split

- Lệnh: `python -m pytest tests/test_split.py`.
- Output: `NOT_VERIFIED` — không có output test riêng được lưu.
- Control: Run B dùng ticket ID từ tên file và mapping tin cậy, không dùng customer ID trong free text attacker.

### 3e. Ledger

- Lệnh: `python -m pytest tests/test_ledger.py`.
- Output: `NOT_VERIFIED` — không có output test riêng được lưu.
- `ledger.verify()`: `NOT_VERIFIED` — chưa có output thực thi trực tiếp.

## Checkpoint 4 — Supply chain và secrets

- Python: `3.13.5`.
- Gitleaks: `v8.30.1`.
- Lỗi đã gặp: `tests/test_supply_chain.py::test_incident_note_identifies_synthetic_leak` fail vì thiếu commit `1bdd849` trong incident note.
- Cách sửa: bổ sung commit `1bdd849`, rule `lab24-synthetic-token`, kết quả quét lịch sử/file hiện tại và hướng dẫn thu hồi/rotate credential thật vào `reports/secrets-incident.md`.
- Lệnh `python -m pytest tests/test_supply_chain.py`: `NOT_VERIFIED` sau khi sửa.
- Lệnh quét Gitleaks lịch sử, quét file hiện tại, `pre-commit run --all-files` và kiểm tra hash lock: `NOT_VERIFIED`.

## Checkpoint 5 — Prove

- Lệnh: `python -m pytest tests/ -q`.
- Exit code: `0`.
- Số test pass/skip: `NOT_VERIFIED` — context hiện có exit code nhưng không có summary output để đếm chính xác.
- `attack-after.log`: lệnh `(Get-Item reports/attack-after.log).Length` trả `0`; kích thước file là `0 byte` và file rỗng.
- `ledger.verify()`: `NOT_VERIFIED` — chưa chạy lệnh xác minh trực tiếp.
- Các lỗi còn lại: chưa có output đầy đủ để xác nhận pass/skip từng test; không đánh dấu đạt bằng suy đoán.