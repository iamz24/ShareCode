from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters
import requests
import re
from bs4 import BeautifulSoup

# Thay token bằng token do bot father cung cấp
token = '7792316991:AAERTsQre4IJeXizwFOg43Z2fQdXcDTustA'

async def start(update: Update, context):
    await update.message.reply_text("Chào bạn! Bot đang làm việc, hãy gửi lệnh để kiểm tra các CVE.")

# Lấy điểm Base Score từ NVD
def get_base_score(cve_id):
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        # Lấy tất cả các thẻ có data-testid phù hợp
        score_tags = soup.find_all("a", {"data-testid": re.compile(r"vuln-cvss3[-a-zA-Z0-9]*-panel-score")})
        scores = []

        for score_tag in score_tags:
            score_text = score_tag.text.strip()  # Ví dụ: "9.8 CRITICAL" hoặc "N/A"
            try:
                score_value = float(score_text.split()[0])  # Lấy số đầu tiên
                scores.append(score_value)
            except ValueError:
                continue  # Nếu không phải số, bỏ qua

        # Trả về điểm số lớn nhất (nếu có điểm >= 9.0)
        if scores:
            max_score = max(scores)
            return max_score if max_score >= 9.0 else None
    except Exception as e:
        print(f"Lỗi lấy dữ liệu {cve_id}: {e}")
    return None

async def cve_check(update: Update, context):
    # Lấy tin nhắn từ người dùng (danh sách CVE)
    cve_message = update.message.text.strip()

    # Sử dụng regex để tách các CVE trong chuỗi
    cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', cve_message)
    results = []  # Danh sách lưu kết quả tìm thấy

    # Kiểm tra từng CVE
    for cve_id in cve_ids:
        score = get_base_score(cve_id)
        if score is not None:
            results.append(f"{cve_id}: {score} (CRITICAL)")

    # Kiểm tra và gửi kết quả nếu có CVE thỏa mãn
    if results:
        await update.message.reply_text("\n".join(results))
    else:
        await update.message.reply_text("Không có CVE nào đạt mức độ nguy hiểm cao.")
    
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
