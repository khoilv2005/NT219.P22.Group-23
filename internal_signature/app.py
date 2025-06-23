# --- Thư viện ---
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import os
from dotenv import load_dotenv
import sys
sys.path.append('dilithium-py/src')
from dilithium_py.ml_dsa import ML_DSA_44
import logging
from datetime import datetime
import hashlib
import io
import cv2
import tempfile
from pyzbar.pyzbar import decode
import pyqrcode
from PIL import Image, ImageDraw, ImageFont
from pdf2image import convert_from_path
from functools import wraps
from create_diploma import tao_bang_dai_hoc_tren_anh
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session
import pyotp
import qrcode
import base64

# --- Cấu hình ứng dụng ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
load_dotenv()
app = Flask(__name__)
app.secret_key = 'a_very_secret_and_secure_key_for_production'
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'bang-chua-ky'
app.config['SIGNED_FOLDER'] = 'bang-da-ky'
db = SQLAlchemy(app)

# --- Cấu hình Flask-Login và Model User ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Vui lòng đăng nhập để truy cập trang này."
login_manager.login_message_category = "warning"

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    full_name = db.Column(db.String(255), nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='nhanvien')
    otp_secret = db.Column(db.String(32))
    otp_enabled = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            self.otp_secret = pyotp.random_base32()

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def roles_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                flash("Bạn không có quyền truy cập chức năng này.", "danger")
                return redirect(url_for('unauthorized'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

@app.route('/unauthorized')
@login_required
def unauthorized():
    return render_template('unauthorized.html')

# --- Routes cho Quản trị (Admin) ---
@app.route('/admin/manage_users')
@roles_required('hieutruong')
def manage_users():
    users = User.query.all()
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/create_user', methods=['GET', 'POST'])
@roles_required('hieutruong')
def create_user():
    if request.method == 'POST':
        username = request.form.get('username')
        full_name = request.form.get('full_name')
        password = request.form.get('password')
        role = request.form.get('role')

        if not username or not password or not role:
            flash("Vui lòng điền đầy đủ thông tin.", "danger")
            return redirect(url_for('create_user'))
            
        if User.query.filter_by(username=username).first():
            flash("Tên người dùng đã tồn tại.", "warning")
            return redirect(url_for('create_user'))

        new_user = User(username=username, role=role, full_name=full_name)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash(f"Đã tạo tài khoản '{username}' thành công.", "success")
        return redirect(url_for('manage_users'))
        
    return render_template('admin/create_user.html')

# --- Routes cho Xác thực ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id_to_auth'] = user.id
            if user.otp_enabled:
                return redirect(url_for('verify_2fa'))
            else:
                return redirect(url_for('setup_2fa'))
        else:
            flash('Tên đăng nhập hoặc mật khẩu không đúng.', 'danger')
            return render_template('login.html')
            
    return render_template('login.html')

@app.route('/setup_2fa', methods=['GET', 'POST'])
def setup_2fa():
    if 'user_id_to_auth' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id_to_auth']
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form.get('token')
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(token):
            user.otp_enabled = True
            db.session.commit()
            session.pop('user_id_to_auth', None)
            login_user(user, remember=True)
            flash('Kích hoạt xác thực hai yếu tố thành công!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Mã xác thực không hợp lệ. Vui lòng thử lại.', 'danger')
            
    otp_uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(name=user.username, issuer_name='HeThongKyVanBangUIT')
    img = qrcode.make(otp_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_code_data = base64.b64encode(buffered.getvalue()).decode()
    return render_template('setup_2fa.html', qr_code_data=qr_code_data)

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'user_id_to_auth' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        user_id = session['user_id_to_auth']
        user = User.query.get(user_id)
        token = request.form.get('token')
        
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(token):
            session.pop('user_id_to_auth', None)
            login_user(user, remember=True)
            return redirect(url_for('index'))
        else:
            flash('Mã xác thực không hợp lệ.', 'danger')
            
    return render_template('verify_2fa.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Bạn đã đăng xuất.', 'info')
    return redirect(url_for('login'))

# --- Các hàm helper ---
def add_text_to_pdf(input_path, output_path, text_to_add, position, font_path="arial.ttf", font_size=100, color=(0, 0, 0)):
    try:
        pages = convert_from_path(input_path, dpi=300, first_page=1, last_page=1)
        if not pages:
            logger.error(f"Không thể chuyển đổi PDF '{input_path}' thành ảnh.")
            return False
        
        doc_img = pages[0]
        draw = ImageDraw.Draw(doc_img)

        try:
            font = ImageFont.truetype(font_path, font_size)
        except IOError:
            logger.warning(f"Không tìm thấy font '{font_path}'. Sử dụng font mặc định.")
            font = ImageFont.load_default()

        draw.text(position, text_to_add, fill=color, font=font)
        doc_img.save(output_path, "PDF", resolution=300)
        return True
    except Exception as e:
        logger.error(f"Lỗi khi ghi chữ vào PDF: {str(e)}")
        return False

def generate_file_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.digest()
    except Exception as e:
        logger.error(f"Hash generation error: {str(e)}")
        raise

def embed_qr_code(original_path, qr_content, output_path):
    try:
        qr = pyqrcode.create(qr_content)
        qr_buffer = io.BytesIO()
        qr.png(qr_buffer, scale=10, module_color=[0, 0, 0, 128], background=[0xff, 0xff, 0xff])
        qr_img = Image.open(qr_buffer)

        if original_path.lower().endswith('.pdf'):
            pages = convert_from_path(original_path, dpi=300, first_page=1, last_page=1)
            doc_img = pages[0]
        else:
            doc_img = Image.open(original_path)

        qr_size = min(int(doc_img.width * 0.1), int(doc_img.height * 0.1))
        qr_img = qr_img.resize((qr_size, qr_size))

        if os.path.basename(original_path).lower() == "bangdaihoc.jpg":
            position = (1522, 1082)
        else:
            margin = 20
            position = (doc_img.width - qr_img.width - margin, doc_img.height - qr_img.height - margin)

        doc_img.paste(qr_img, position, qr_img if qr_img.mode == 'RGBA' else None)

        if original_path.lower().endswith('.pdf'):
            doc_img.save(output_path, "PDF", resolution=300)
        else:
            doc_img.save(output_path)
        return True
    except Exception as e:
        logger.error(f"QR embedding error: {str(e)}")
        return False

# --- Routes nghiệp vụ ---
@app.route('/')
@login_required
def index():
    query = text("SELECT * FROM SinhVien WHERE Status = 'pending' ORDER BY NgayTao DESC")
    result = db.session.execute(query)
    sinh_viens = result.fetchall()
    return render_template('thongtin.html', sinh_viens=sinh_viens)

@app.route('/sign/<string:student_mssv>', methods=['GET', 'POST'])
@roles_required('hieutruong')
def sign(student_mssv):
    if request.method == 'POST':
        path_with_signer = None
        temp_final_path = None
        try:
            student_info = db.session.execute(text("SELECT * FROM SinhVien WHERE MSSV = :mssv"), {"mssv": student_mssv}).fetchone()
            if not student_info:
                flash('Không tìm thấy thông tin sinh viên', 'error')
                return redirect(url_for('index'))
            
            unsigned_diploma_path = os.path.join(app.config['UPLOAD_FOLDER'], f'bang_{student_mssv}.pdf')
            if not os.path.exists(unsigned_diploma_path):
                flash('Không tìm thấy file bằng chưa ký!', 'error')
                return redirect(url_for('index'))

            public_key_id = request.form.get('public_key_id')
            private_key_file = request.files.get('private_key_file')
            if not public_key_id or not private_key_file:
                flash('Vui lòng chọn public key và file private key', 'error')
                return redirect(request.url)

            # 1. Thêm tên người ký vào bằng
            signer_name = current_user.full_name or current_user.username
            path_with_signer = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_signer_{student_mssv}.pdf")
            if not add_text_to_pdf(unsigned_diploma_path, path_with_signer, signer_name, position=(4450, 3421)):
                flash('Lỗi khi thêm tên người ký vào bằng.', 'error')
                return redirect(request.url)

            # 2. Nhúng mã QR vào bằng ĐÃ CÓ TÊN người ký
            temp_final_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_final_{student_mssv}.pdf")
            verify_url = f'https://khoaviper.shop/verify?mssv={student_mssv}'
            if not embed_qr_code(path_with_signer, verify_url, temp_final_path):
                flash('Lỗi khi nhúng mã QR', 'error')
                return redirect(request.url)

            # 3. Ký file cuối cùng và cập nhật DB
            private_key = private_key_file.read().decode('utf-8').strip()
            doc_hash = generate_file_hash(temp_final_path)
            signature = ML_DSA_44.sign(bytes.fromhex(private_key), doc_hash)
            
            signature_query = text("INSERT INTO Signature (Student_MSSV, PublicKey_ID, Document_Hash, Signature) VALUES (:mssv, :pk_id, :hash, :sig)")
            db.session.execute(signature_query, {
                "mssv": student_mssv,
                "pk_id": public_key_id,
                "hash": doc_hash.hex(),
                "sig": signature.hex()
            })
            
            db.session.execute(text("UPDATE SinhVien SET Status = 'signed' WHERE MSSV = :mssv"), {"mssv": student_mssv})
            db.session.commit()

            # 4. Hoàn tất và dọn dẹp
            os.makedirs(app.config['SIGNED_FOLDER'], exist_ok=True)
            signed_path = os.path.join(app.config['SIGNED_FOLDER'], f"signed_bang_{student_mssv}.pdf")
            os.rename(temp_final_path, signed_path)
            
            flash(f'Ký bằng tốt nghiệp thành công!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            logger.error(f"Lỗi trong quá trình ký: {str(e)}")
            flash(f'Quá trình ký thất bại: {str(e)}', 'error')
            return redirect(request.url)
        finally:
            # Dọn dẹp các file tạm
            if path_with_signer and os.path.exists(path_with_signer):
                os.remove(path_with_signer)
            if temp_final_path and os.path.exists(temp_final_path):
                 os.remove(temp_final_path)


    # Logic cho GET request
    student = db.session.execute(text("SELECT * FROM SinhVien WHERE MSSV = :mssv"), {"mssv": student_mssv}).fetchone()
    public_keys = db.session.execute(text("SELECT id, Name, CreateDate, CreateTime FROM PublicKeys ORDER BY CreateDate DESC, CreateTime DESC")).fetchall()
    return render_template('sign.html', student=student, public_keys=public_keys)

@app.route('/generate-keys')
@roles_required('hieutruong')
def key_generator():
    return render_template('key_generator.html')

@app.route('/generate_keys', methods=['POST'])
@roles_required('hieutruong')
def generate_keys():
    try:
        data = request.get_json()
        key_name = data.get('name', '').strip()
        if not key_name:
            return jsonify({'error': 'Vui lòng nhập tên khóa'}), 400

        public_key, private_key = ML_DSA_44.keygen()
        public_key_hex = public_key.hex()
        private_key_hex = private_key.hex()

        query = text("INSERT INTO PublicKeys (Name, Public_Key, CreateDate, CreateTime) VALUES (:name, :public_key, CURRENT_DATE, CURRENT_TIME)")
        db.session.execute(query, {'name': key_name, 'public_key': public_key_hex})
        db.session.commit()

        return jsonify({'private_key_bytes': private_key_hex, 'message': 'Tạo cặp khóa thành công!'})
    except Exception as e:
        logger.error(f"Key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/ds-sinh-vien')
@login_required
def ds_sinh_vien():
    query = text("SELECT * FROM SinhVien ORDER BY NgayTao DESC")
    result = db.session.execute(query)
    sinh_viens = result.fetchall()
    return render_template('index.html', sinh_viens=sinh_viens)

@app.route('/them-sinh-vien', methods=['GET', 'POST'])
@roles_required('nhanvien', 'hieutruong')
def them_sinh_vien():
    if request.method == 'POST':
        try:
            query = text("INSERT INTO SinhVien (MSSV, Ten, NamVaoTruong, NamTotNghiep, XepLoai) VALUES (:mssv, :ten, :nam_vao_truong, :nam_tot_nghiep, :xep_loai)")
            mssv = request.form['mssv']
            ten = request.form['ten']
            nam_vao_truong = request.form['nam_vao_truong']
            nam_tot_nghiep = request.form['nam_tot_nghiep']
            xep_loai = request.form['xep_loai']
            
            db.session.execute(query, {
                'mssv': mssv, 'ten': ten, 'nam_vao_truong': nam_vao_truong,
                'nam_tot_nghiep': nam_tot_nghiep, 'xep_loai': xep_loai
            })
            db.session.commit()

            output_path = os.path.join(app.config['UPLOAD_FOLDER'], f'bang_{mssv}.pdf')
            tao_bang_dai_hoc_tren_anh(
                ten=ten, xep_loai=xep_loai,
                nam_tot_nghiep=f"{nam_vao_truong} - {nam_tot_nghiep}",
                output_path=output_path
            )

            flash('Thêm sinh viên thành công!', 'success')
            return redirect(url_for('ds_sinh_vien'))
        except Exception as e:
            flash(f'Có lỗi xảy ra: {str(e)}', 'error')
            return redirect(url_for('them_sinh_vien'))
    
    return render_template('them_sinh_vien.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=999, debug=True)
