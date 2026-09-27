from test_data import *
from policy import POLICY


def json_search(key, input_object, role=None):
    """
    Tìm kiếm đệ quy key trong đối tượng JSON (dict/list lồng nhau)
    và áp dụng kiểm soát truy cập dựa trên vai trò (RBAC).
    """

    if key in POLICY and role is not None:
        if role not in POLICY[key]:
            return []

    ret_val = []

    # Xử lý trường hợp input_object là dictionary
    if isinstance(input_object, dict):
        for k, v in input_object.items():
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

    # Xử lý trường hợp input_object là list
    elif isinstance(input_object, list):
        for val in input_object:
            if not isinstance(val, (str, int)):
                ret_val.extend(json_search(key, val, role))

    return ret_val


if __name__ == "__main__":
    print("--- Test với key 'issueSummary' ---")
    print(json_search("issueSummary", data))
    print("\n--- Test với key 'apiKey' và role 'viewer' (Cấm truy cập) ---")
    print(json_search("apiKey", data, role="viewer"))
    print("\n--- Test với key 'apiKey' và role 'admin' (Cho phép) ---")
    print(json_search("apiKey", data, role="admin"))
