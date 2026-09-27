# 🛡️ SECURITY REQUIREMENTS SPECIFICATION - JSON_SEARCH()

## 1. Overview & Purpose
Tài liệu này xác định các **Yêu cầu An toàn Phần mềm** bắt buộc phải triển khai cho hàm `json_search()` trong module `recursive_json_search.py`. Các yêu cầu này được xây dựng dựa trên kết quả phân tích mối đe dọa nhằm ngăn ngừa rò rỉ dữ liệu hạ tầng mạng nhạy cảm.

---

## 2. Access Control Policy Matrix
Căn cứ vào bảng chính sách `POLICY` trong `policy.py`, quyền RBAC được quy định nghiêm ngặt như sau:

| Trường dữ liệu (`key`) | Mô tả tài sản | Mức độ nhạy cảm | Vai trò được phép truy cập (`allowed_roles`) |
| :--- | :--- | :--- | :--- |
| `apiKey` | Khóa xác thực SNMP | **Critical** | `["admin"]` |
| `managementIpAddress` | Địa chỉ IP quản lý | **High** | `["admin", "operator"]` |
| `issueSummary` | Tóm tắt sự cố | **Low** | `["admin", "operator", "viewer"]` |

---

## 3. Mandatory Security Requirements

### **SR-01: Thực thi Phân quyền theo Vai trò**
* **Mô tả:** Cập nhật chữ ký hàm thành `json_search(key, input_object, role=None)`.
* **Quy tắc:** Khi nhận yêu cầu tra cứu một `key`, hàm phải kiểm tra tham số `role` đối chiếu với chính sách `POLICY`. Nếu `role` không thuộc danh sách `allowed_roles` của `key` đó, hàm phải từ chối truy xuất dữ liệu.

### **SR-02: Bảo vệ Tính Bảo mật của Dữ liệu**
* **SR-02.1:** Khóa xác thực `apiKey` **chỉ** được phép trả về kết quả khi `role == "admin"`. Tất cả các vai trò khác (`operator`, `viewer`, `None`) đều nhận về danh sách rỗng `[]`.
* **SR-02.2:** Địa chỉ IP `managementIpAddress` chỉ được phép trả về cho vai trò `admin` và `operator`. Vai trò `viewer` hoặc `None` bị từ chối truy cập và nhận về `[]`.
* **SR-02.3:** Trường `issueSummary` cho phép cả 3 vai trò `admin`, `operator`, và `viewer` truy cập.

### **SR-03: Nguyên tắc Từ chối Mặc định**
* **Mô tả:** Trong các trường hợp dưới đây, hàm `json_search()` phải lập tức trả về danh sách rỗng `[]`:
  1. Người gọi hàm không truyền tham số `role` (`role=None`).
  2. Giá trị `role` không hợp lệ hoặc không tồn tại trong định nghĩa hệ thống (ví dụ: `role="guest"`).
  3. Tìm kiếm `key` thuộc danh sách nhạy cảm nhưng người dùng không có quyền.
* **Ngăn ngừa rò rỉ Exception:** Hàm phải xử lý fail-safe, không bắn ra ngoại lệ hoặc làm rò rỉ cấu trúc hệ thống.

---

## 4. Security Testing Acceptance Criteria
Bộ kiểm thử an toàn trong `test_json_search.py` phải xác minh thành công các kịch bản sau:

1. **`test_api_key_limited_to_admin`:** Gọi `json_search("apiKey", data, role="viewer")` hoặc `role="operator"` -> Kết quả trả về `[]`.
2. **`test_management_ip_access`:** Gọi `json_search("managementIpAddress", data, role="viewer")` -> Kết quả trả về `[]`; gọi với `role="operator"` hoặc `role="admin"` -> Kết quả trả về danh sách IP hợp lệ.
3. **`test_unauthenticated_access_denied`:** Gọi `json_search("apiKey", data, role=None)` hoặc `role="invalid_role"` -> Kết quả trả về `[]`.
