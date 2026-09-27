# 🕵️ THREAT MODELING REPORT - JSON_SEARCH()

## 1. System Context & Scope
* **Tên thành phần:** Hàm tra cứu đệ quy `json_search(key, input_object, role=None)`.
* **Mục đích:** Bóc tách và tra cứu các thông tin quản lý mạng từ cấu trúc JSON đệ quy (dict/list lồng nhau) do API giám sát hạ tầng (Cisco DNA Center / Network Controller) phản hồi.
* **Các Vai trò Người dùng (Actors/Roles):**
  * `admin`: Quản trị viên hệ thống mạng (có quyền hạn cao nhất).
  * `operator`: Nhân viên vận hành và giám sát kĩ thuật.
  * `viewer`: Người dùng xem báo cáo/hệ thống giám sát chỉ đọc.

---

## 2. Asset Identification
Dựa trên phân tích các trường dữ liệu JSON mẫu trong hệ thống giám sát:

| Tài sản (Asset) | Mô tả & Loại thông tin | Mức độ nhạy cảm | Hậu quả nếu rò rỉ |
| :--- | :--- | :--- | :--- |
| `apiKey` | Chuỗi SNMP Community String / Token xác thực thiết bị | **Cực kỳ nghiêm trọng** | Kẻ tấn công có thể truy cập trực tiếp và can thiệp vào cấu hình thiết bị mạng. |
| `managementIpAddress` | Địa chỉ IP quản lý nội bộ của thiết bị mạng | **Cao** | Do thám sơ đồ mạng và thực hiện các đợt tấn công mục tiêu vào IP quản lý. |
| `issueSummary` | Thông tin tóm tắt về sự cố thiết bị | **Trung bình / Công khai nội bộ** | Rò rỉ trạng thái hoạt động nhưng không gây nguy hại trực tiếp tới an toàn hạ tầng. |

---

## 3. Trust Boundaries & Weaknesses
* **Trust Boundary:** Giữa tầng người dùng gọi hàm (với vai trò `role` được cấp) và cơ sở dữ liệu thô nhạy cảm chứa trong đối tượng JSON.
* **Điểm yếu kiến trúc (Architectural Vulnerability):**
  Hàm `json_search()` nguyên bản không thực hiện xác thực tham số `role`, không kiểm tra danh sách quyền trước khi trích xuất và trả về dữ liệu. Mọi yêu cầu truy vấn với `key` hợp lệ đều trả về dữ liệu thô.

---

## 4. Threat Analysis using STRIDE (Phân tích Mối đe dọa)

### Bảng tổng hợp mối đe dọa STRIDE:

| Mã mối đe dọa | Nhóm STRIDE | Mô tả mối đe dọa | Tác động | Mức độ rủi ro | Mẫu khai thác |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **T-01** | **Information Disclosure** | Người dùng có vai trò `viewer` hoặc `operator` yêu cầu trích xuất khóa `apiKey` của thiết bị mạng. | Rò rỉ thông tin xác thực SNMP, mất an toàn toàn bộ hệ thống mạng. | **Critical** | `json_search("apiKey", data, role="viewer")` trả về chuỗi API key nhạy cảm. |
| **T-02** | **Information Disclosure** | Người dùng vai trò `viewer` yêu cầu lấy danh sách địa chỉ `managementIpAddress`. | Lộ địa chỉ IP hạ tầng quản lý, phục vụ cho do thám và tấn công leo leo. | **High** | `json_search("managementIpAddress", data, role="viewer")` trả về danh sách IP. |
| **T-03** | **Elevation of Privilege / Bypass** | Người dùng gọi hàm không truyền tham số `role` (`role=None`) hoặc truyền role giả mạo để vượt qua cơ chế phân quyền. | Người dùng vô danh (Unauthenticated) lấy được dữ liệu nhạy cảm như một Admin. | **Critical** | `json_search("apiKey", data, role=None)` trả về dữ liệu bí mật. |

---

## 5. Risk Mitigation Strategy
* Bắt buộc thực hiện **Role-Based Access Control** trong hàm `json_search()`.
* Tra cứu chính sách truy cập `POLICY` định nghĩa sẵn trong `policy.py` trước khi thực thi đệ quy.
* Áp dụng nguyên tắc **Default Deny**: Mọi truy vấn không có `role` hợp lệ hoặc không đủ thẩm quyền phải lập tức trả về danh sách rỗng `[]`.
