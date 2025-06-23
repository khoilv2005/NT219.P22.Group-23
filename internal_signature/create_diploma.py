from PIL import Image, ImageDraw, ImageFont

def tao_bang_dai_hoc_tren_anh(ten, xep_loai, nam_tot_nghiep, output_path):
    template_path = "bangdaihoc.jpg"
    font_path = "arial.ttf"
    
    try:
        image = Image.open(template_path)
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file ảnh '{template_path}'. Vui lòng kiểm tra lại.")
        return

    try:
        # Tăng kích thước font cho tên để nổi bật hơn
        font_ten = ImageFont.truetype(font_path, size=80) 
        font_normal = ImageFont.truetype(font_path, size=45)
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file font '{font_path}'. Vui lòng kiểm tra lại.")
        return

    draw = ImageDraw.Draw(image)

    text_color = (20, 20, 20) # Màu chữ hơi xám đậm cho tự nhiên hơn

    # --- TỌA ĐỘ ĐÃ ĐƯỢC CẬP NHẬT ---
    # Tọa độ X được đưa về gần giữa trang hơn (khoảng 885)
    ten_vi_tri = (655, 710) 
    # Tinh chỉnh lại vị trí Xếp loại và Niên khóa
    xep_loai_vi_tri = (440, 880)
    nien_khoa_vi_tri = (445, 970)
    
    # Sử dụng anchor="mm" để căn giữa theo cả chiều ngang và dọc
    draw.text(ten_vi_tri, ten.upper(), font=font_ten, fill=text_color, anchor="mm") 
    draw.text(xep_loai_vi_tri, xep_loai, font=font_normal, fill=text_color)
    draw.text(nien_khoa_vi_tri, str(nam_tot_nghiep), font=font_normal, fill=text_color)
    
    if image.mode == 'RGBA':
        image = image.convert('RGB')
        
    image.save(output_path, "PDF", resolution=100.0)
    print(f"Đã tạo bằng tốt nghiệp thành công! Lưu tại: {output_path}") 