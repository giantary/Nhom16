from test_data import *
from policy import POLICY


def json_search(key, input_object, role=None):
    """
    Tìm kiếm đệ quy key trong đối tượng JSON (dict/list lồng nhau)
    và áp dụng kiểm soát truy cập theo vai trò (RBAC).
    """
    # 1. Kiểm tra phân quyền RBAC dựa trên policy
    if key in POLICY:
        if role is not None and role not in POLICY[key]:
            return []

    ret_val = []

    # 2. Xử lý trường hợp input_object là dictionary
    if isinstance(input_object, dict):
        for k, v in input_object.items():
            # Nếu tìm thấy key khớp -> Thêm vào kết quả
            if k == key:
                temp = {k: v}
                ret_val.append(temp)

            # Đệ quy xuống tầng con và dùng extend() để gộp kết quả
            if isinstance(v, dict):
                ret_val.extend(json_search(key, v, role))
            elif isinstance(v, list):
                for item in v:
                    if not isinstance(item, (str, int)):
                        ret_val.extend(json_search(key, item, role))

    # 3. Xử lý trường hợp input_object là list
    elif isinstance(input_object, list):
        for val in input_object:
            if not isinstance(val, (str, int)):
                ret_val.extend(json_search(key, val, role))

    return ret_val


if __name__ == "__main__":
    print("--- Test với role 'viewer' cho key 'issueSummary' ---")
    print(json_search("issueSummary", data, role="viewer"))

    print("\n--- Test với role 'viewer' cho key 'apiKey' (Không có quyền) ---")
    print(json_search("apiKey", data, role="viewer"))
