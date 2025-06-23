import os
from flask import Flask, request, flash, redirect, render_template, url_for
from flask_sqlalchemy import SQLAlchemy

# 1. KHỞI TẠO VÀ CẤU HÌNH ỨNG DỤNG
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# 2. ĐỊNH NGHĨA DATABASE MODELS
class SignedDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_name = db.Column(db.String(150), nullable=False)
    document_hash = db.Column(db.String(256), nullable=False, unique=True)
    public_key = db.Column(db.String(512), nullable=False)
    signature = db.Column(db.String(512), nullable=False)

    def __repr__(self):
        return f'<SignedDocument {self.document_name}>'

class SinhVien(db.Model):
    __tablename__ = 'SinhVien'
    mssv = db.Column(db.String(20), primary_key=True)
    ho_ten = db.Column(db.String(100), nullable=False)
    nam_vao_truong = db.Column(db.Integer)
    nam_tot_nghiep = db.Column(db.Integer)
    xep_loai = db.Column(db.String(50))
    trang_thai = db.Column(db.String(50))

    def __repr__(self):
        return f'<SinhVien {self.mssv}>'

# 4. ĐỊNH NGHĨA CÁC ROUTES
@app.route('/')
def index():
    return 'Chào mừng đến với ứng dụng xác thực!'

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        if 'document' not in request.files:
            flash('Vui lòng chọn file', 'error')
            return redirect(request.url)

        file = request.files['document']
        if file.filename == '':
            flash('Vui lòng chọn file', 'error')
            return redirect(request.url)

        try:
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(temp_path)

            current_hash_bytes = generate_file_hash(temp_path)
            current_hash_hex = current_hash_bytes.hex()
            
            doc = SignedDocument.query.filter_by(document_hash=current_hash_hex).first()

            if not doc:
                flash('Xác thực thất bại! Tài liệu không hợp lệ hoặc không tồn tại trong hệ thống.', 'error')
                return render_template('verify.html', verified=True, valid=False)

            hash_valid = True
            sig_valid = ML_DSA_44.verify(bytes.fromhex(doc.public_key),
                                          current_hash_bytes,
                                          bytes.fromhex(doc.signature))

            if sig_valid:
                flash('Xác thực thành công! Tài liệu hợp lệ.', 'success')
            else:
                flash('Xác thực thất bại! Chữ ký không hợp lệ.', 'error')

            return render_template('verify.html',
                                   verified=True,
                                   valid=sig_valid,
                                   filename=doc.document_name,
                                   hash_valid=hash_valid,
                                   sig_valid=sig_valid)

        except Exception as e:
            app.logger.error(f"Verification error: {str(e)}")
            flash('Quá trình xác thực xảy ra lỗi', 'error')
            return redirect(request.url)

    student_id = request.args.get('student_id')
    if student_id:
        student = SinhVien.query.get(student_id)
        if student:
            return render_template('student_info.html', student=student)
        else:
            flash(f'Không tìm thấy sinh viên có MSSV: {student_id}', 'error')
            return redirect(url_for('verify'))

    return render_template('verify.html')

# 5. KHỞI CHẠY ỨNG DỤNG
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)