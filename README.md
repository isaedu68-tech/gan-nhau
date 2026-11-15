# Gần Nhau

Chat, nghe nhạc, xem phim cùng nhau – dành cho cặp đôi và nhóm nhỏ (2–6 người).

**Dùng:** https://isaedu68-tech.github.io/gn/

## Bảo mật

- **Kết nối thẳng** giữa các máy (WebRTC). Không máy chủ nào nhận, đọc hay lưu tin nhắn, ảnh, phim.
- **Hai lớp khoá:** link mời (mã phòng + khoá link, nằm sau dấu `#`, không gửi lên máy chủ) và **mật khẩu phòng** báo bằng lời.
  Khoá = PBKDF2-SHA256(khoá link + mật khẩu, 310 000 vòng): nửa đầu mã hoá thông tin bắt tay, nửa sau là khoá AES-GCM 256
  mã hoá thêm mọi dữ liệu của app, chồng lên lớp DTLS của WebRTC.
- **Chủ phòng duyệt** từng người, có thể khoá phòng. Chưa được duyệt thì không nhận / gửi được gì.
- **Mã xác minh** từng người = băm(vân tay chứng chỉ DTLS hai máy + khoá phòng): đọc cho nhau để chắc không ai đứng giữa.
- **Không tài nguyên ngoài:** phông chữ tự chứa, Content-Security-Policy chỉ cho chạy mã của trang;
  YouTube (Google) chỉ tải khi người dùng đồng ý, qua youtube-nocookie.com. Ảnh gửi đi được xoá thông tin ẩn (GPS…).
- Tìm nhau qua relay Nostr công cộng: relay chỉ thấy dữ liệu bắt tay **đã mã hoá** và địa chỉ IP. Người trong phòng thấy IP của nhau (bản chất kết nối thẳng).

Mã nguồn công khai để ai cũng kiểm tra được. Mỗi lần đăng, `SHA256SUMS.txt` liệt kê dấu vân tay của từng file trên trang.
Bản Android (chặn chụp màn hình, mã nằm sẵn trong máy) phát hành riêng.
