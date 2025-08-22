from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
import ssl
import socket
import time

app = Flask(__name__)

class WebsiteAudit:
    def __init__(self, url):
        self.url = url if url.startswith("http") else "http://" + url
        self.issues = {"security": [], "performance": [], "seo": [], "accessibility": []}
        self.soup = None
        self.response = None

    def fetch_website(self):
        try:
            start = time.time()
            self.response = requests.get(self.url, timeout=10)
            self.load_time = time.time() - start
            if self.response.status_code == 200:
                self.soup = BeautifulSoup(self.response.text, 'html.parser')
            else:
                self.issues["performance"].append(f"Page returned status code {self.response.status_code}")
        except Exception as e:
            self.issues["performance"].append(f"Failed to fetch website: {e}")

    def analyze_security(self):
        if not self.response:
            self.issues["security"].append("No response from server to analyze security.")
            return

        if not self.url.startswith("https://"):
            self.issues["security"].append("Website does not use HTTPS. Enable HTTPS for security.")
        else:
            try:
                hostname = self.url.split("//")[1].split("/")
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                    s.settimeout(5)
                    s.connect((hostname, 443))
                    cert = s.getpeercert()
                    not_after = cert['notAfter']
                    self.issues["security"].append(f"SSL certificate valid until {not_after}")
            except Exception as e:
                self.issues["security"].append(f"SSL certificate check failed: {e}")

        headers = self.response.headers
        if "Content-Security-Policy" not in headers:
            self.issues["security"].append("Missing Content-Security-Policy header. Protects against XSS.")
        if "X-Content-Type-Options" not in headers:
            self.issues["security"].append("Missing X-Content-Type-Options header to prevent MIME-sniffing.")
        if "Strict-Transport-Security" not in headers:
            self.issues["security"].append("Missing Strict-Transport-Security header to enforce HTTPS.")

    def analyze_performance(self):
        if hasattr(self, 'load_time'):
            if self.load_time > 3:
                self.issues["performance"].append(f"Page load time is {self.load_time:.2f}s. Aim for under 3 seconds.")
        else:
            self.issues["performance"].append("Page load time could not be measured.")

        images = self.soup.find_all('img') if self.soup else []
        for img in images:
            src = img.get('src')
            if src and src.startswith('http'):
                try:
                    head = requests.head(src, timeout=5)
                    size = int(head.headers.get('Content-Length', 0))
                    if size > 500000:
                        self.issues["performance"].append(f"Image {src} is large ({size/1024:.1f} KB). Optimize image size.")
                except:
                    continue

    def analyze_seo(self):
        if not self.soup:
            self.issues["seo"].append("HTML content could not be parsed. SEO check skipped.")
            return

        if not self.soup.title or not self.soup.title.string.strip():
            self.issues["seo"].append("Missing or empty <title> tag.")
        if not self.soup.find('meta', attrs={'name': 'description'}):
            self.issues["seo"].append("Missing meta description tag.")
        h1s = self.soup.find_all('h1')
        if len(h1s) == 0:
            self.issues["seo"].append("No <h1> tag found.")
        elif len(h1s) > 1:
            self.issues["seo"].append("Multiple <h1> tags found.")

    def analyze_accessibility(self):
        if not self.soup:
            self.issues["accessibility"].append("HTML content could not be parsed. Accessibility check skipped.")
            return

        images = self.soup.find_all('img')
        for img in images:
            if not img.get('alt'):
                self.issues["accessibility"].append(f"Image missing alt attribute: {img.get('src','unknown source')}")

        html_tag = self.soup.find('html')
        if not html_tag or not html_tag.get('lang'):
            self.issues["accessibility"].append("Missing 'lang' attribute in <html> tag.")

    def run_audit(self):
        self.fetch_website()
        self.analyze_security()
        self.analyze_performance()
        self.analyze_seo()
        self.analyze_accessibility()
        return self.issues

@app.route("/", methods=["GET", "POST"])
def home():
    report = None
    url = ""
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            audit = WebsiteAudit(url)
            report = audit.run_audit()
    return render_template("index.html", report=report, url=url)

if __name__ == "__main__":
    app.run(debug=True)
