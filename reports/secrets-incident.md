# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks v8.30.1, dùng rule `lab24-synthetic-token` trong `.gitleaks.toml`.
- Commit chứa token giả: `1bdd849`.
- File, rule và kết quả quét lịch sử: Gitleaks phát hiện token synthetic trong lịch sử Git tại commit `1bdd849`, theo rule `lab24-synthetic-token`.
- Kết quả quét file hiện tại: Không phát hiện token giả trong các file hiện tại sau khi token đã được loại khỏi `HEAD`.
- Nếu đây là credential thật, cần thu hồi/rotate ngay tại dịch vụ cấp token, kiểm tra việc sử dụng trái phép, rồi xử lý mọi bản sao còn tồn tại trong repository, lịch sử Git, cache, log và các bản sao lưu.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ: Xoá file ở commit mới không làm token cũ trong lịch sử Git tự vô hiệu. Token thật vẫn có thể bị lấy lại từ các commit cũ, clone hoặc bản sao lưu, nên phải thu hồi tại dịch vụ cấp token. Việc pin dependency chỉ kiểm soát phiên bản dependency, không xử lý secret đã bị lộ.