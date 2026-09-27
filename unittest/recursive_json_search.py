from policy import POLICY

def json_search(key, input_object, role=None):
    ret_val = []
    
    # Kiem tra quyen truy cap (RBAC) dua tren policy.py
    # Neu key nam trong POLICY va role cua nguoi dung khong duoc phep truy cap key do, thi bo qua (tra ve list rong).
    if key in POLICY:
        allowed_roles = POLICY[key]
        if role not in allowed_roles:
            return ret_val # Role khong hop le, khong tra ve ket qua
            
    if isinstance(input_object, dict):
        for k, v in input_object.items():
            if k == key:
                temp = {k: v}
                ret_val.append(temp)
            if isinstance(v, dict):
                # Su dung extend thay vi chi goi de quy de gop danh sach ket qua vao ret_val (Fix loi YC4)
                ret_val.extend(json_search(key, v, role))
            elif isinstance(v, list):
                for item in v:
                    if not isinstance(item, (str, int)):
                        ret_val.extend(json_search(key, item, role))
    elif isinstance(input_object, list):
        for val in input_object:
            if not isinstance(val, (str, int)):
                ret_val.extend(json_search(key, val, role))
                
    return ret_val
