import os
import sys
import json
import time
import threading
import hashlib
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet

# ==================== CẤU HÌNH VÀ CÁC HÀM HELPER ====================

# Dán chìa khóa bí mật bạn đã tạo vào đây
SECRET_KEY = os.getenv('ENCRYPTION_KEY', 'a_default_key_that_is_not_secure').encode()
cipher_suite = Fernet(SECRET_KEY)

DB_FILENAME = "users.dat" # Tên file database trên server
file_lock = threading.Lock()

def create_secure_hash(password: str) -> str:
    """Băm mật khẩu bằng SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def write_encrypted_json(data: dict):
    """Ghi và mã hóa dữ liệu vào file."""
    try:
        json_data = json.dumps(data, indent=2).encode('utf-8')
        encrypted_data = cipher_suite.encrypt(json_data)
        with open(DB_FILENAME, 'wb') as f:
            f.write(encrypted_data)
        return True
    except Exception as e:
        print(f"Error writing encrypted file: {e}", file=sys.stderr)
        return False

def read_encrypted_json() -> dict | None:
    """Đọc và giải mã dữ liệu từ file."""
    try:
        with open(DB_FILENAME, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode('utf-8'))
    except FileNotFoundError:
        print("INFO: users.dat not found. Creating a new one with default admin.")
        # Nếu file không tồn tại, tự tạo admin
        initial_data = {
            "DatGold": {
                "password_hash": create_secure_hash("Emperor123@"),
                "role": "admin",
                "hwid": None,
                "public_ip": None
            }
        }
        if write_encrypted_json(initial_data):
            return initial_data
        return None
    except Exception as e:
        print(f"Error reading or decrypting file: {e}", file=sys.stderr)
        return None

# ==================== KHỞI TẠO APP FLASK ====================

app = Flask(__name__)

# ==================== CÁC API ENDPOINT ====================

@app.route('/')
def index():
    return "API Server is running."

@app.route('/login', methods=['POST'])
def handle_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    current_hwid = data.get('hwid')
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # Lấy địa chỉ IP đầu tiên trong chuỗi và xóa khoảng trắng
        current_public_ip = forwarded_for.split(',')[0].strip()
    else:
        # Dùng remote_addr làm phương án dự phòng
        current_public_ip = request.remote_addr

    if not all([username, password, current_hwid, current_public_ip]):
        return jsonify({"status": "error", "message": "Missing required data"}), 400
    with file_lock:
        users = read_encrypted_json()
        if users is None:
            return jsonify({"status": "error", "message": "Database corrupted on server"}), 500

        user_data = users.get(username)

        if not (user_data and create_secure_hash(password) == user_data.get("password_hash")):
            return jsonify({"status": "error", "message": "Invalid username or password"})

        if user_data.get("role") == "admin":
            return jsonify({"status": "success", "role": "admin", "username": username})

        if user_data.get('role') != 'admin' and user_data.get('status') == 'online':
            return jsonify({"status": "error", "message": "This account is already online on another device."})
        
        users[username]['status'] = 'online'
        users[username]['last_seen'] = int(time.time())
        users[username]['hwid'] = current_hwid
        users[username]['public_ip'] = current_public_ip
        write_encrypted_json(users)
        return jsonify({
            "status": "success", 
            "role": user_data.get("role"), 
            "username": username,
            "message": f"Welcome, {username}!"
        })

    return jsonify({"status": "error", "message": "Liên hệ admin."})

# --- Các API cho Admin ---
def is_admin_authenticated(request_data):
    admin_user = request_data.get('admin_username')
    admin_pass = request_data.get('admin_password')
    if not all([admin_user, admin_pass]): return False
    
    users = read_encrypted_json()
    admin_data = users.get(admin_user)

    if admin_data and admin_data.get('role') == 'admin' and create_secure_hash(admin_pass) == admin_data.get('password_hash'):
        return True
    return False

@app.route('/register', methods=['POST'])
def handle_register():
    data = request.get_json()
    if not is_admin_authenticated(data):
        return jsonify({"status": "error", "message": "Authentication failed"}), 401
    
    new_username = data.get('new_username')
    new_password = data.get('new_password')

    if not all([new_username, new_password]):
        return jsonify({"status": "error", "message": "Missing new username or password"}), 400
        
    with file_lock:
        users = read_encrypted_json()
        if users is None:
            return jsonify({"status": "error", "message": "Database corrupted on server"}), 500

        if new_username in users:
            return jsonify({"status": "error", "message": "Username already exists"})
        
        # Thêm người dùng mới vào biến users (trong bộ nhớ)
        users[new_username] = {
            "password_hash": create_secure_hash(new_password), 
            "role": "user", 
            "hwid": None,
            "public_ip": None,
            "status": "offline",
            "last_seen": 0
        }
    
        if write_encrypted_json(users):
            # Nếu ghi thành công, trả về success
            return jsonify({"status": "success", "message": f"User '{new_username}' created."})
        else:
            # Nếu ghi thất bại, trả về lỗi
            return jsonify({"status": "error", "message": "Failed to save user"}), 500

@app.route('/users', methods=['POST'])
def get_users():
    data = request.get_json()
    if not is_admin_authenticated(data):
        return jsonify({"status": "error", "message": "Authentication failed"}), 401
    
    users = read_encrypted_json()
    safe_user_list = {
        user: {
            "role": data.get("role"),
            "hwid": data.get("hwid"), 
            "public_ip": data.get("public_ip"),
            "status": data.get("status", "offline"),
            "last_seen": data.get("last_seen", 0)
            }
        for user, data in users.items()
    }
    return jsonify({"status": "success", "users": safe_user_list})

@app.route('/reset-status', methods=['POST'])
def handle_reset_status():
    data = request.get_json()
    if not is_admin_authenticated(data):
        return jsonify({"status": "error", "message": "Authentication failed"}), 401
        
    username_to_reset = data.get('username')
    with file_lock:
        users = read_encrypted_json()
        if users and username_to_reset in users and users[username_to_reset].get("role") != "admin":
            # Đặt lại trạng thái về offline
            users[username_to_reset]["status"] = "offline"
            write_encrypted_json(users)
            return jsonify({"status": "success", "message": f"Status for '{username_to_reset}' has been reset to offline."})
        else:
            return jsonify({"status": "error", "message": "User not found or is an admin."})
    return jsonify({"status": "error", "message": "Failed to reset status."}), 500

@app.route('/delete-user', methods=['POST'])
def handle_delete_user():
    data = request.get_json()
    if not is_admin_authenticated(data):
        return jsonify({"status": "error", "message": "Authentication failed"}), 401
        
    username_to_delete = data.get('username')
    with file_lock:
        users = read_encrypted_json()
        if username_to_delete in users and users[username_to_delete].get("role") != "admin":
            del users[username_to_delete]
            write_encrypted_json(users)
            return jsonify({"status": "success", "message": f"User '{username_to_delete}' has been deleted."})
        else:
            return jsonify({"status": "error", "message": "User not found or is an admin."})
    return jsonify({"status": "error", "message": "Failed to delete user."}), 500

@app.route('/heartbeat', methods=['POST'])
def handle_heartbeat():
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({"status": "error", "message": "Username required"}), 400
    with file_lock:
        users = read_encrypted_json()
        if users and username in users:
            users[username]['status'] = 'online'
            users[username]['last_seen'] = int(time.time()) # Ghi lại timestamp hiện tại
            write_encrypted_json(users)
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "User not found"}), 404
    return jsonify({"status": "error", "message": "Failed to update heartbeat"}), 500

@app.route('/logout', methods=['POST'])
def handle_logout():
    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({"status": "error", "message": "Username required"}), 400

    users = read_encrypted_json()
    if users and username in users:
        users[username]['status'] = 'offline'
        write_encrypted_json(users)
        return jsonify({"status": "success"})

    return jsonify({"status": "error", "message": "User not found"}), 404

@app.route('/check-offline', methods=['GET'])
def check_offline_users():
    with file_lock:
        users = read_encrypted_json()
        if not users:
            return "No users to check", 200

        now = int(time.time())
        timeout_seconds = 120 # 2 phút
        changed = False

        for username, data in users.items():
            if data.get('status') == 'online':
                last_seen = data.get('last_seen', 0)
                if now - last_seen > timeout_seconds:
                    print(f"User {username} timed out. Marking as offline.")
                    users[username]['status'] = 'offline'
                    changed = True
        
        if changed:
            write_encrypted_json(users)

        return "Offline check complete", 200
    return "Failed to check offline users", 500

# Lệnh để chạy thử trên máy local, không dùng khi deploy
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
