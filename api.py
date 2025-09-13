import os
import sys
import time
import hashlib
import psycopg2
from flask import Flask, request, jsonify

# ==================== CẤU HÌNH DATABASE ====================

# Lấy chuỗi kết nối từ biến môi trường đã thiết lập trên Render
DATABASE_URL = os.getenv('DATABASE_URL')

def get_db_connection():
    """Tạo và trả về một kết nối tới database."""
    try:
        # Kiểm tra xem DATABASE_URL có tồn tại không
        if not DATABASE_URL:
            print("FATAL: DATABASE_URL environment variable is not set.", file=sys.stderr)
            return None
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except psycopg2.OperationalError as e:
        print(f"FATAL: Could not connect to the database: {e}", file=sys.stderr)
        return None

# ==================== CÁC HÀM HELPER ====================

def create_secure_hash(password: str) -> str:
    """Băm mật khẩu bằng SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# ==================== KHỞI TẠO APP FLASK ====================

app = Flask(__name__)

# ==================== CÁC API ENDPOINT ====================

@app.route('/')
def index():
    # Kiểm tra kết nối database khi vào trang chủ
    conn = get_db_connection()
    if conn:
        conn.close()
        return "API Server is running and successfully connected to PostgreSQL."
    else:
        return "API Server is running BUT FAILED to connect to PostgreSQL. Check DATABASE_URL environment variable.", 500


@app.route('/login', methods=['POST'])
def handle_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    current_hwid = data.get('hwid')
    
    current_public_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

    if not all([username, password, current_hwid]):
        return jsonify({"status": "error", "message": "Missing required data"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Database connection error"}), 500
        
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT password_hash, role, status FROM users WHERE username = %s",
                (username,)
            )
            user_record = cursor.fetchone()

            if not (user_record and create_secure_hash(password) == user_record[0]):
                return jsonify({"status": "error", "message": "Invalid username or password"})

            role, status = user_record[1], user_record[2]

            if role == "admin":
                return jsonify({"status": "success", "role": "admin", "username": username})

            if role != 'admin' and status == 'online':
                return jsonify({"status": "error", "message": "This account is already online."})
            
            cursor.execute(
                """
                UPDATE users 
                SET status = 'online', last_seen = %s, hwid = %s, public_ip = %s 
                WHERE username = %s
                """,
                (int(time.time()), current_hwid, current_public_ip, username)
            )
            conn.commit()
            
            return jsonify({
                "status": "success", 
                "role": role, 
                "username": username,
                "message": f"Welcome, {username}!"
            })
    except psycopg2.Error as e:
        print(f"Login DB Error: {e}", file=sys.stderr)
        return jsonify({"status": "error", "message": "An internal error occurred"}), 500
    finally:
        if conn:
            conn.close()

# --- Các API cho Admin ---
def is_admin_authenticated(request_data):
    admin_user = request_data.get('admin_username')
    admin_pass = request_data.get('admin_password')
    if not all([admin_user, admin_pass]): return False
    
    conn = get_db_connection()
    if not conn: return False
    
    is_valid = False
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT password_hash FROM users WHERE username = %s AND role = 'admin'",
                (admin_user,)
            )
            admin_record = cursor.fetchone()
            if admin_record and create_secure_hash(admin_pass) == admin_record[0]:
                is_valid = True
    except psycopg2.Error as e:
        print(f"Admin Auth DB Error: {e}", file=sys.stderr)
    finally:
        if conn:
            conn.close()
    return is_valid

@app.route('/register', methods=['POST'])
def handle_register():
    data = request.get_json()
    if not is_admin_authenticated(data):
        return jsonify({"status": "error", "message": "Authentication failed"}), 401
    
    new_username = data.get('new_username')
    new_password = data.get('new_password')

    if not all([new_username, new_password]):
        return jsonify({"status": "error", "message": "Missing new username or password"}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Database connection error"}), 500

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, role, status, last_seen)
                VALUES (%s, %s, 'user', 'offline', 0)
                """,
                (new_username, create_secure_hash(new_password))
            )
            conn.commit()
            return jsonify({"status": "success", "message": f"User '{new_username}' created."})
    except psycopg2.IntegrityError:
        conn.rollback()
        return jsonify({"status": "error", "message": "Username already exists"})
    except psycopg2.Error as e:
        conn.rollback()
        print(f"Register DB Error: {e}", file=sys.stderr)
        return jsonify({"status": "error", "message": "Failed to save user"}), 500
    finally:
        if conn:
            conn.close()


@app.route('/users', methods=['POST'])
def get_users():
    data = request.get_json()
    if not is_admin_authenticated(data):
        return jsonify({"status": "error", "message": "Authentication failed"}), 401
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Database connection error"}), 500

    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT username, role, hwid, public_ip, status, last_seen FROM users")
            users_list = {}
            for row in cursor.fetchall():
                users_list[row[0]] = {
                    "role": row[1], "hwid": row[2], "public_ip": row[3],
                    "status": row[4], "last_seen": row[5]
                }
            return jsonify({"status": "success", "users": users_list})
    except psycopg2.Error as e:
        print(f"Get Users DB Error: {e}", file=sys.stderr)
        return jsonify({"status": "error", "message": "Could not fetch users"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/reset-status', methods=['POST'])
def handle_reset_status():
    data = request.get_json()
    if not is_admin_authenticated(data):
        return jsonify({"status": "error", "message": "Authentication failed"}), 401
        
    username_to_reset = data.get('username')
    conn = get_db_connection()
    if not conn: return jsonify({"status": "error", "message": "Database error"}), 500
    
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE users SET status = 'offline' WHERE username = %s AND role != 'admin'",
                (username_to_reset,)
            )
            conn.commit()
            if cursor.rowcount > 0:
                return jsonify({"status": "success", "message": f"Status for '{username_to_reset}' has been reset."})
            else:
                return jsonify({"status": "error", "message": "User not found or is an admin."})
    except psycopg2.Error as e:
        conn.rollback()
        print(f"Reset Status DB Error: {e}", file=sys.stderr)
        return jsonify({"status": "error", "message": "Failed to reset status."}), 500
    finally:
        if conn:
            conn.close()


@app.route('/delete-user', methods=['POST'])
def handle_delete_user():
    data = request.get_json()
    if not is_admin_authenticated(data):
        return jsonify({"status": "error", "message": "Authentication failed"}), 401
        
    username_to_delete = data.get('username')
    conn = get_db_connection()
    if not conn: return jsonify({"status": "error", "message": "Database error"}), 500
    
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM users WHERE username = %s AND role != 'admin'",
                (username_to_delete,)
            )
            conn.commit()
            if cursor.rowcount > 0:
                return jsonify({"status": "success", "message": f"User '{username_to_delete}' has been deleted."})
            else:
                return jsonify({"status": "error", "message": "User not found or is an admin."})
    except psycopg2.Error as e:
        conn.rollback()
        print(f"Delete User DB Error: {e}", file=sys.stderr)
        return jsonify({"status": "error", "message": "Failed to delete user."}), 500
    finally:
        if conn:
            conn.close()


@app.route('/heartbeat', methods=['POST'])
def handle_heartbeat():
    data = request.get_json()
    username = data.get('username')
    if not username: return jsonify({"status": "error", "message": "Username required"}), 400
    
    conn = get_db_connection()
    if not conn: return jsonify({"status": "error", "message": "Database error"}), 500
    
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE users SET status = 'online', last_seen = %s WHERE username = %s",
                (int(time.time()), username)
            )
            conn.commit()
            if cursor.rowcount > 0:
                return jsonify({"status": "success"})
            else:
                return jsonify({"status": "error", "message": "User not found"}), 404
    except psycopg2.Error as e:
        conn.rollback()
        print(f"Heartbeat DB Error: {e}", file=sys.stderr)
        return jsonify({"status": "error", "message": "Failed to update heartbeat"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/logout', methods=['POST'])
def handle_logout():
    data = request.get_json()
    username = data.get('username')
    if not username: return jsonify({"status": "error", "message": "Username required"}), 400
    
    conn = get_db_connection()
    if not conn: return jsonify({"status": "error", "message": "Database error"}), 500
    
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE users SET status = 'offline' WHERE username = %s",
                (username,)
            )
            conn.commit()
            if cursor.rowcount > 0:
                return jsonify({"status": "success"})
            else:
                return jsonify({"status": "error", "message": "User not found"}), 404
    except psycopg2.Error as e:
        conn.rollback()
        print(f"Logout DB Error: {e}", file=sys.stderr)
        return jsonify({"status": "error", "message": "Logout failed"}), 500
    finally:
        if conn:
            conn.close()


@app.route('/check-offline', methods=['GET'])
def check_offline_users():
    timeout_seconds = 120
    now = int(time.time())
    
    conn = get_db_connection()
    if not conn: return "Database connection error", 500

    try:
        with conn.cursor() as cursor:
            # Câu lệnh UPDATE hiệu quả hơn nhiều so với việc lặp bằng Python
            cursor.execute(
                "UPDATE users SET status = 'offline' WHERE status = 'online' AND %s - last_seen > %s",
                (now, timeout_seconds)
            )
            conn.commit()
            print(f"Offline check complete. {cursor.rowcount} users were marked as offline.")
            return "Offline check complete", 200
    except psycopg2.Error as e:
        conn.rollback()
        print(f"Check Offline DB Error: {e}", file=sys.stderr)
        return "Failed to check offline users", 500
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
