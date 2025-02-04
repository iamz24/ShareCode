from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters
import requests
import re
from bs4 import BeautifulSoup

# Thay token bằng token do bot father cung cấp
token = '7792316991:AAERTsQre4IJeXizwFOg43Z2fQdXcDTustA'

async def start(update: Update, context):
    await update.message.reply_text("Chào bạn! Bot đang làm việc, hãy gửi lệnh để kiểm tra các CVE.")

async def cve_check(update: Update, context):
    # Lấy tin nhắn từ người dùng (danh sách CVE)
    cve_message = update.message.text.strip()

    # Sử dụng regex để tách các CVE trong chuỗi
    cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', cve_message)

    results = []  # Danh sách lưu kết quả tìm thấy

    # Kiểm tra từng CVE
    for cve_id in cve_ids:
        url = f'https://nvd.nist.gov/vuln/detail/{cve_id}'

        # Gửi yêu cầu HTTP đến NVD và lấy dữ liệu
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Tìm điểm Base Score trong trang
        base_score_element = soup.find('a', {'data-testid': 'vuln-cvss3-cna-panel-score'})

        if base_score_element:
            base_score_text = base_score_element.get_text(strip=True).split(' ')[0]

            try:
                base_score = float(base_score_text)

                if base_score >= 9.0:
                    results.append(f"{cve_id}: {base_score} (CRITICAL)")
            except ValueError:
                # Nếu không thể chuyển đổi điểm số sang float, bỏ qua CVE này
                continue

    # Kiểm tra và gửi kết quả nếu có CVE thỏa mãn
    if results:
        # Nếu có CVE có điểm số >= 9.0, gửi kết quả
        await update.message.reply_text("\n".join(results))
    
    # Sau khi tìm xong, gửi thông báo "Đã tìm hết"
    await update.message.reply_text("Đã tìm hết.")

def main():
    # Tạo ứng dụng Telegram và thiết lập bot
    application = Application.builder().token(token).build()

    # Đăng ký lệnh /start
    application.add_handler(CommandHandler("start", start))

    # Đăng ký xử lý tin nhắn cho CVE
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, cve_check))

    # Chạy bot
    application.run_polling()

if __name__ == '__main__':
    main()
