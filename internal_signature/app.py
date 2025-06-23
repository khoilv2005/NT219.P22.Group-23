from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import os
from dotenv import load_dotenv
from create_diploma import tao_bang_dai_hoc_tren_anh
from PIL import Image, ImageDraw, ImageFont
# Load biến môi trường từ file .env
load_dotenv()

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Cần thiết cho flash messages

# Cấu hình kết nối MySQL từ biến môi trường
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Khởi tạo database
db = SQLAlchemy(app)

@app.route('/')
def home():
    # Lấy danh sách sinh viên
    query = text("SELECT * FROM SinhVien ORDER BY NgayTao DESC")
    result = db.session.execute(query)
    sinh_viens = result.fetchall()
    return render_template('index.html', sinh_viens=sinh_viens)

@app.route('/them-sinh-vien', methods=['GET', 'POST'])
def them_sinh_vien():
    if request.method == 'POST':
        try:
            # Sử dụng text() để khai báo SQL query
            query = text("""
            INSERT INTO SinhVien (MSSV, Ten, NamVaoTruong, NamTotNghiep, XepLoai)
            VALUES (:mssv, :ten, :nam_vao_truong, :nam_tot_nghiep, :xep_loai)
            """)
            
            mssv = request.form['mssv']
            ten = request.form['ten']
            nam_vao_truong = request.form['nam_vao_truong']
            nam_tot_nghiep = request.form['nam_tot_nghiep']
            xep_loai = request.form['xep_loai']
            
            db.session.execute(query, {
                'mssv': mssv,
                'ten': ten,
                'nam_vao_truong': nam_vao_truong,
                'nam_tot_nghiep': nam_tot_nghiep,
                'xep_loai': xep_loai
            })
            db.session.commit()

            # Tạo bằng đại học
            output_path = os.path.join('bang-chua-ky', f'bang_{mssv}.pdf')
            tao_bang_dai_hoc_tren_anh(
                ten=ten,
                xep_loai=xep_loai,
                nam_tot_nghiep=f"{nam_vao_truong} - {nam_tot_nghiep}",
                output_path=output_path
            )

            flash('Thêm sinh viên thành công và đã tạo bằng!', 'success')
            return redirect(url_for('home'))
        except Exception as e:
            flash(f'Có lỗi xảy ra: {str(e)}', 'error')
            return redirect(url_for('them_sinh_vien'))
    
    return render_template('them_sinh_vien.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=999, debug=True) 