# Hệ thống Quản lý Động Thực Vật

## Tổng quan

Hệ thống Quản lý Động Thực Vật là một ứng dụng web hiện đại được thiết kế để quản lý thông tin về các loài động thực vật. Dự án này cung cấp một nền tảng toàn diện để tổ chức và quản lý dữ liệu về các ban, ngành, bộ, và loài trong hệ thống phân loại sinh học.

## Tính năng chính

- **Quản lý phân loại**: Hỗ trợ quản lý chi tiết các cấp độ phân loại như ban, ngành, bộ, họ, chi, và loài.
- **Hệ thống xác thực**: Tích hợp Spring Security để quản lý đăng nhập và phân quyền người dùng.
- **Phân quyền dựa trên vai trò**: Phân biệt quyền truy cập giữa người dùng thông thường và quản trị viên.
- **Quản lý phiên đăng nhập**: Sử dụng JWT (JSON Web Tokens) để quản lý phiên đăng nhập an toàn và hiệu quả.
## Cấu trúc bảo mật

### Xác thực người dùng
- Sử dụng Spring Security để xác thực người dùng.
- JWT được tạo sau khi đăng nhập thành công và được sử dụng cho các yêu cầu tiếp theo.

### Phân quyền
- **Người dùng (User)**: Có quyền xem (GET) thông tin.
- **Quản trị viên (Admin)**: Có toàn quyền truy cập (GET, POST, PUT, DELETE).

### Quản lý Token
- JWT được sử dụng để duy trì phiên đăng nhập và xác thực người dùng.
- Token chứa thông tin về vai trò của người dùng để thực hiện phân quyền.

