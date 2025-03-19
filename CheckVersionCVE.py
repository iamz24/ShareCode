from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup

def fetch_cve_details(cve_id):
    # Tạo URL dựa trên CVE ID
    base_url = "https://www.cve.org/CVERecord?id="
    url = f"{base_url}{cve_id}"

    # Cấu hình ChromeDriver với options cho chế độ headless
    options = Options()
    options.add_argument("--headless")  # Chạy không hiển thị giao diện trình duyệt
    options.add_argument("--disable-gpu")  # Tắt GPU để tiết kiệm tài nguyên
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

    try:
        # Mở URL
        driver.get(url)

        # Chờ cho đến khi phần tử chứa thông tin 'Product Status' tải xong
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "cve-product-status-container"))
        )

        # Lấy nội dung HTML của trang
        soup = BeautifulSoup(driver.page_source, "html.parser")

        # Tìm container chứa thông tin 'Product Status'
        product_status_container = soup.find("div", id="cve-product-status-container")
        if not product_status_container:
            print(f"Không tìm thấy thông tin 'Product Status' cho {cve_id}.")
            return

        # Lấy danh sách thông tin từng sản phẩm
        products = product_status_container.find_all("div", id="cve-vendor-product-platforms")
        for product in products:
            vendor = product.find("p", class_="cve-product-status-heading", string="Vendor").find_next_sibling("p").text.strip()
            product_name = product.find("p", class_="cve-product-status-heading", string="Product").find_next_sibling("p").text.strip()
            platforms = product.find("p", class_="cve-product-status-heading", string="Platforms").find_next_sibling("p").text.strip()

            print(f"Vendor: {vendor}")
            print(f"Product: {product_name}")
            print(f"Platforms: {platforms}")

            # Lấy thông tin về các phiên bản
            versions_container = product.find("div", id="cve-affected-unaffected-unknown-versions")
            if versions_container:
                versions = versions_container.find_all("li")
                for version in versions:
                    version_text = version.text.strip()
                    # Tách thông tin phiên bản thành "Từ ... đến trước ..."
                    if "before" in version_text and "affected from" in version_text:
                        affected_from = version_text.split("affected from")[1].split("before")[0].strip()
                        affected_before = version_text.split("before")[1].strip()
                        print(f"Affected: Từ phiên bản {affected_from} đến trước phiên bản {affected_before}")
                    else:
                        print(f"Affected: {version_text}")

            print("-" * 40)

    except Exception as e:
        print(f"Lỗi khi xử lý trang: {e}")
    finally:
        driver.quit()

# Nhập CVE từ người dùng
cve_id = input("Nhập CVE ID (ví dụ: CVE-2024-38063): ")
fetch_cve_details(cve_id)
