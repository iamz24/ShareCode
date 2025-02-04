import requests
from bs4 import BeautifulSoup
import re

# Đọc dữ liệu từ file
def read_cve_from_file(file_path):
    with open(file_path, 'r') as file:
        return file.read().strip()

# Tách các CVE ID từ chuỗi
def extract_cve_ids(cve_string):
    return re.findall(r'CVE-\d{4}-\d{5,}', cve_string)

# Lấy điểm Base Score từ NVD
def get_base_score(cve_id):
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = requests.get(url, headers=headers, timeout=1000)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        # Lấy tất cả các thẻ với các data-testid khác nhau
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

# Lọc và in các CVE có Base Score >= 9.0
def filter_high_risk_cves(cve_list):
    for cve in cve_list:
        score = get_base_score(cve)
        if score is not None:
            print(f"{cve}: {score} (CRITICAL)")

# Main
input_file = "cve_list.txt"  # File chứa chuỗi CVE liền nhau
cve_string = read_cve_from_file(input_file)

# Tách các CVE ID
cve_ids = extract_cve_ids(cve_string)

# Kiểm tra các CVE có Base Score >= 9.0
filter_high_risk_cves(cve_ids)
