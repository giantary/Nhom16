import unittest
from test_data import data, key1, key2
from recursive_json_search import json_search


class json_search_test(unittest.TestCase):
    """Module kiểm thử chức năng và an toàn (RBAC) cho hàm json_search() trong recursive_json_search.py"""

    # =============================================================
    # Functional Unit Tests
    # =============================================================
    def test_search_found(self):
        """Kiểm tra tìm kiếm key1 ('issueSummary') thành công, trả về danh sách không rỗng."""
        self.assertTrue([] != json_search(key1, data))

    def test_search_not_found(self):
        """Kiểm tra tìm kiếm key2 không tồn tại, trả về danh sách rỗng."""
        self.assertTrue([] == json_search(key2, data))

    def test_is_a_list(self):
        """Kiểm tra kiểu dữ liệu trả về luôn là dạng list."""
        self.assertIsInstance(json_search(key1, data), list)

    # =============================================================
    # Security Unit Tests
    # =============================================================
    def test_wrong_role_cannot_read_secret(self):
        """Kiểm tra role không có quyền (viewer, operator) không được phép đọc apiKey (chỉ admin)."""
        self.assertEqual([], json_search("apiKey", data, role="viewer"))
        self.assertEqual([], json_search("apiKey", data, role="operator"))
        # Admin được phép đọc
        self.assertTrue(len(json_search("apiKey", data, role="admin")) > 0)

    def test_management_ip_allows_operator_but_not_viewer(self):
        """Kiểm tra operator và admin đọc được managementIpAddress, viewer bị từ chối."""
        self.assertEqual([], json_search("managementIpAddress", data, role="viewer"))
        self.assertTrue(len(json_search("managementIpAddress", data, role="operator")) > 0)
        self.assertTrue(len(json_search("managementIpAddress", data, role="admin")) > 0)

    def test_issue_summary_allows_configured_roles(self):
        """Kiểm tra issueSummary cho phép tất cả các role trong policy (admin, operator, viewer)."""
        for r in ["admin", "operator", "viewer"]:
            self.assertTrue(len(json_search("issueSummary", data, role=r)) > 0)

    def test_invalid_role_returns_empty(self):
        """Kiểm tra role không hợp lệ (không thuộc POLICY) bị từ chối truy cập trường nhạy cảm."""
        self.assertEqual([], json_search("apiKey", data, role="guest"))
        self.assertEqual([], json_search("managementIpAddress", data, role="unauthorized_role"))


if __name__ == "__main__":
    unittest.main()
