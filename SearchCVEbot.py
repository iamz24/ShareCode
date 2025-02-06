import re
import asyncio
import requests
from bs4 import BeautifulSoup

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ConversationHandler,
    filters,
    ContextTypes,
)

# Thư viện Selenium và các module liên quan
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Thay token bằng token do BotFather cung cấp
token = 'token'

# ------------------ HÀM XỬ LÝ CVE (get_base_score) ------------------ #
def get_base_score(cve_id):
    """
    Lấy điểm Base Score từ trang NVD cho CVE cụ thể.
    """
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        # Tìm các thẻ chứa điểm CVSS3 (ví dụ: "9.8 CRITICAL")
        score_tags = soup.find_all("a", {"data-testid": re.compile(r"vuln-cvss3[-a-zA-Z0-9]*-panel-score")})
        scores = []
        for score_tag in score_tags:
            score_text = score_tag.text.strip()
            try:
                score_value = float(score_text.split()[0])
                scores.append(score_value)
            except ValueError:
                continue
        if scores:
            max_score = max(scores)
            return max_score if max_score >= 9.0 else None
    except Exception as e:
        print(f"Lỗi lấy dữ liệu cho {cve_id}: {e}")
    return None

# ------------------ HÀM XỬ LÝ VERSION ------------------ #
def fetch_cve_details(cve_id):
    base_url = "https://www.cve.org/CVERecord?id="
    url = f"{base_url}{cve_id}"

    options = Options()
    options.add_argument("--headless")  # Chạy ẩn
    options.add_argument("--disable-gpu")
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

    output_lines = []
    try:
        driver.get(url)
        # Chờ container chứa thông tin 'Product Status' xuất hiện
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "cve-product-status-container"))
        )

        soup = BeautifulSoup(driver.page_source, "html.parser")
        product_status_container = soup.find("div", id="cve-product-status-container")
        if not product_status_container:
            output_lines.append(f"Không tìm thấy thông tin 'Product Status' cho {cve_id}.")
            return "\n".join(output_lines)

        products = product_status_container.find_all("div", id="cve-vendor-product-platforms")
        if not products:
            output_lines.append(f"Không tìm thấy thông tin sản phẩm cho {cve_id}.")

        for product in products:
            # Lấy thông tin Vendor, Product, Platforms
            vendor_tag = product.find("p", class_="cve-product-status-heading", string="Vendor")
            vendor = vendor_tag.find_next_sibling("p").text.strip() if vendor_tag else "N/A"
            product_tag = product.find("p", class_="cve-product-status-heading", string="Product")
            product_name = product_tag.find_next_sibling("p").text.strip() if product_tag else "N/A"
            platforms_tag = product.find("p", class_="cve-product-status-heading", string="Platforms")
            platforms = platforms_tag.find_next_sibling("p").text.strip() if platforms_tag else "N/A"

            # Ghép các thông tin lại thành một chuỗi
            combined_info = f"{vendor} {product_name} {platforms}"

            # Xử lý thông tin về phiên bản bị ảnh hưởng
            versions_container = product.find("div", id="cve-affected-unaffected-unknown-versions")
            if versions_container:
                versions = versions_container.find_all("li")
                for version in versions:
                    version_text = version.text.strip()
                    if "before" in version_text and "affected from" in version_text:
                        try:
                            # Lấy phần thông tin version từ version_text
                            affected_from = version_text.split("affected from")[1].split("before")[0].strip()
                            affected_before = version_text.split("before")[1].strip()
                            output_lines.append(f"Affected: {combined_info} Từ phiên bản {affected_from} đến trước phiên bản {affected_before}")
                        except Exception:
                            output_lines.append(f"Affected: {combined_info} {version_text}")
                    else:
                        output_lines.append(f"Affected: {combined_info} {version_text}")
            else:
                # Nếu không có thông tin version, in luôn combined_info
                output_lines.append(f"Affected: {combined_info}")

            output_lines.append("-" * 40)

    except Exception as e:
        output_lines.append(f"Lỗi khi xử lý trang: {e}")
    finally:
        driver.quit()
    return "\n".join(output_lines)

def split_message_by_block(message, max_length=4000, separator="\n----------------------------------------\n"):
    """
    Cắt chuỗi message thành danh sách các phần sao cho:
    - Không cắt giữa block (block được phân cách bởi separator).
    - Mỗi phần có độ dài không vượt quá max_length.
    
    Nếu một block vượt quá max_length thì sẽ bị cắt buộc.
    """
    blocks = message.split(separator)
    messages = []
    current_message = ""
    
    for i, block in enumerate(blocks):
        block = block.strip()
        if i < len(blocks) - 1:
            block += separator
        else:
            block += "\n"
        
        if len(current_message) + len(block) > max_length:
            if current_message:
                messages.append(current_message)
            current_message = block
        else:
            current_message += block
            
    if current_message:
        messages.append(current_message)
    return messages

# ------------------ STATE CHO CONVERSATION ------------------ #
CHECK_CVE = 1
CHECK_VERSION = 2

# ------------------ CÁC HANDLER CHO CONVERSATION ------------------ #
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Chào bạn! Bot đang làm việc.\n"
        "Sử dụng /checkcve để vào chế độ lọc CVE Critical.\n"
        "Sử dụng /checkversion để vào chế độ kiểm tra phiên bản bị ảnh hưởng.\n"
        "Trong chế độ, chỉ cần gửi danh sách hoặc CVE cần kiểm tra. Gõ /back để thoát chế độ hiện tại."
    )

async def checkcve_entry(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Bạn đã chuyển sang chế độ **checkcve**.\n"
        "Hãy gửi tin nhắn chứa danh sách các CVE (ví dụ: `CVE-2021-34527 CVE-2022-12345`).\n"
        "Gõ /back để thoát hoặc /checkversion để chuyển chế độ khác.",
        parse_mode="Markdown"
    )
    return CHECK_CVE

async def checkversion_entry(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Bạn đã chuyển sang chế độ **checkversion**.\n"
        "Hãy gửi tin nhắn chứa một CVE (ví dụ: `CVE-2024-38063`) để lấy thông tin phiên bản bị ảnh hưởng.\n"
        "Gõ /back để thoát hoặc /checkcve để chuyển chế độ khác.",
        parse_mode="Markdown"
    )
    return CHECK_VERSION

async def back_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Đã thoát khỏi chế độ hiện tại. Sử dụng /checkcve hoặc /checkversion để bắt đầu chế độ mới."
    )
    return ConversationHandler.END

async def process_cve_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Xử lý tin nhắn gửi khi ở chế độ checkcve.
    """
    cve_message = update.message.text
    cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', cve_message)
    if not cve_ids:
        await update.message.reply_text("Không tìm thấy định dạng CVE hợp lệ. Vui lòng kiểm tra lại.")
        return CHECK_CVE

    results = []
    for cve_id in cve_ids:
        # Chạy hàm get_base_score trong thread riêng để tránh block event loop
        score = await asyncio.to_thread(get_base_score, cve_id)
        if score is not None:
            results.append(f"{cve_id}: {score} (CRITICAL)")
    if results:
        await update.message.reply_text("\n".join(results))
    else:
        await update.message.reply_text("Không có CVE nào đạt mức độ nguy hiểm cao.")
    await update.message.reply_text("Đã kiểm tra xong, bạn có thể gửi thêm danh sách CVE khác, hoặc gõ /back để thoát.")
    return CHECK_CVE

async def process_version_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Xử lý tin nhắn gửi khi ở chế độ checkversion.
    """
    text = update.message.text
    match = re.search(r'CVE-\d{4}-\d{4,7}', text)
    if not match:
        await update.message.reply_text("Không tìm thấy định dạng CVE hợp lệ. Vui lòng kiểm tra lại.")
        return CHECK_VERSION

    cve_id = match.group(0)
    details = await asyncio.to_thread(fetch_cve_details, cve_id)
    parts = split_message_by_block(details)
    for part in parts:
        await update.message.reply_text(part)
    await update.message.reply_text("Hoàn tất kiểm tra, bạn có thể gửi thêm CVE khác, hoặc gõ /back để thoát.")
    return CHECK_VERSION

# ------------------ KHỞI CHẠY BOT ------------------ #
def main():
    application = Application.builder().token(token).build()

    # ConversationHandler để chuyển đổi giữa chế độ checkcve và checkversion
    conv_handler = ConversationHandler(
        entry_points=[
            CommandHandler("checkcve", checkcve_entry),
            CommandHandler("checkversion", checkversion_entry),
        ],
        states={
            CHECK_CVE: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, process_cve_input),
                CommandHandler("checkversion", checkversion_entry),
                CommandHandler("back", back_command)
            ],
            CHECK_VERSION: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, process_version_input),
                CommandHandler("checkcve", checkcve_entry),
                CommandHandler("back", back_command)
            ]
        },
        fallbacks=[CommandHandler("back", back_command)]
    )

    # Đăng ký các handler
    application.add_handler(CommandHandler("start", start))
    application.add_handler(conv_handler)

    # Chạy bot (polling)
    application.run_polling()

if __name__ == '__main__':
    main()
