import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash
import getpass
import pyotp

# Tải biến môi trường từ file .env
load_dotenv()

# --- Cấu hình kết nối ---
DATABASE_URI = f"mysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"

try:
    engine = create_engine(DATABASE_URI)
    Session = sessionmaker(bind=engine)
    db_session = Session()
    print("--- KẾT NỐI DATABASE THÀNH CÔNG ---")
except Exception as e:
    print(f"[LỖI] Không thể kết nối đến cơ sở dữ liệu: {e}")
    exit()

# --- Bắt đầu tạo tài khoản ---
print("\n--- TẠO TÀI KHOẢN HIỆU TRƯỞNG (ADMIN) ---")

# Lấy thông tin từ người dùng
username = input("Nhập tên đăng nhập cho hiệu trưởng: ")
full_name = input("Nhập họ và tên đầy đủ: ")
password = getpass.getpass("Nhập mật khẩu: ")
confirm_password = getpass.getpass("Xác nhận lại mật khẩu: ")

if not username or not password:
    print("\n[LỖI] Tên đăng nhập và mật khẩu không được để trống.")
    exit()

if password != confirm_password:
    print("\n[LỖI] Mật khẩu không khớp. Vui lòng chạy lại kịch bản.")
    exit()

# Kiểm tra xem người dùng đã tồn tại chưa
check_user_query = text("SELECT username FROM users WHERE username = :username")
existing_user = db_session.execute(check_user_query, {'username': username}).fetchone()

if existing_user:
    print(f"\n[LỖI] Tên người dùng '{username}' đã tồn tại.")
    db_session.close()
    exit()

# Băm mật khẩu và tạo các giá trị cần thiết
password_hash = generate_password_hash(password)
role = 'hieutruong'
otp_secret = pyotp.random_base32()
otp_enabled = False

# Tạo câu lệnh SQL để chèn người dùng mới
insert_query = text("""
    INSERT INTO users (username, full_name, password_hash, role, otp_secret, otp_enabled)
    VALUES (:username, :full_name, :password_hash, :role, :otp_secret, :otp_enabled)
""")

try:
    db_session.execute(insert_query, {
        'username': username,
        'full_name': full_name,
        'password_hash': password_hash,
        'role': role,
        'otp_secret': otp_secret,
        'otp_enabled': otp_enabled
    })
    db_session.commit()
    print(f"\n[THÀNH CÔNG] Đã tạo tài khoản hiệu trưởng '{username}'!")
    print("Bây giờ bạn có thể đăng nhập bằng tài khoản này để sử dụng các chức năng quản trị.")
except Exception as e:
    db_session.rollback()
    print(f"\n[LỖI] Có lỗi xảy ra khi tạo tài khoản: {e}")
finally:
    db_session.close()
