# How to use:
# 1. For SSL/TLS mode, first generate a certificate and key:
#    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
# 2. Run the script: python3 simple_waf.py
# 3. Follow the on-screen prompts to configure the WAF.

import http.server
import socketserver
import requests
import re
import ssl
from urllib.parse import unquote_plus, urljoin

# --- Global Configuration (will be set by user input) ---
CONFIG = {}

class WAFRequestHandler(http.server.BaseHTTPRequestHandler):
    """
    The request handler for our WAF proxy server.
    It inspects, blocks, or forwards requests and rewrites responses.
    """
    def is_malicious(self, text_to_check: str) -> bool:
        """ Checks a given string for malicious patterns (SQLi and XSS). """
        if not text_to_check: return False
        decoded_text = unquote_plus(text_to_check)
        sql_patterns = [r"(\'|\"|;|--|\b(UNION|SELECT|INSERT|DELETE|UPDATE|DROP|CREATE|ALTER|EXEC)\b)", r"(\'|\")\s*OR\s*(\'|\")\d+(\'|\")\s*=\s*(\'|\")\d+(\'|\")"]
        for pattern in sql_patterns:
            if re.search(pattern, decoded_text, re.IGNORECASE):
                print(f"🚨 WAF Alert: Potential SQL Injection detected! Pattern: {pattern}, Data: {decoded_text[:100]}")
                return True
        xss_patterns = [r"<script.*?>.*?</script>", r"\b(onerror|onload|onmouseover|onclick|onfocus|onblur)\s*="]
        for pattern in xss_patterns:
            if re.search(pattern, decoded_text, re.IGNORECASE):
                print(f"🚨 WAF Alert: Potential XSS detected! Pattern: {pattern}, Data: {decoded_text[:100]}")
                return True
        return False

    def send_block_page_content(self):
        """ Reads and sends the content of the HTML block page. """
        try:
            with open(CONFIG['ERROR_PAGE_FILE'], 'rb') as f: error_html = f.read()
            self.send_response(403)
            self.send_header("Content-type", "text/html")
            self.send_header("Content-Length", str(len(error_html)))
            self.end_headers()
            self.wfile.write(error_html)
        except FileNotFoundError:
            print(f"⚠️  Warning: '{CONFIG['ERROR_PAGE_FILE']}' not found. Sending plain text error.")
            self.send_error(403, "Forbidden: Malicious request detected.")

    def do_request(self, method):
        """ Handles all incoming requests (GET, POST, etc.) """
        if self.path == CONFIG['BLOCKED_REQUEST_PATH']:
            self.send_block_page_content()
            return

        content_length = int(self.headers.get('Content-Length', 0))
        request_body = self.rfile.read(content_length)
        is_request_malicious = self.is_malicious(self.path) or self.is_malicious(request_body.decode('utf-8', errors='ignore'))
        
        if is_request_malicious:
            self.send_response(302)
            self.send_header('Location', CONFIG['BLOCKED_REQUEST_PATH'])
            self.end_headers()
            return

        try:
            target_url = f"http://{CONFIG['TARGET_HOST']}:{CONFIG['TARGET_PORT']}{self.path}"
            proxy_headers = {key: value for key, value in self.headers.items()}
            proxy_headers['Host'] = CONFIG['TARGET_HOST']

            # IMPORTANT: When WAF talks to backend, ignore SSL cert verification if backend is also HTTPS
            response = requests.request(
                method, target_url, headers=proxy_headers,
                data=request_body, allow_redirects=False, timeout=10, verify=False
            )

            self.send_response(response.status_code)
            
            target_host_bytes = CONFIG['TARGET_HOST'].encode('utf-8')
            proxy_ip_bytes = CONFIG['PROXY_IP_FOR_REWRITING'].encode('utf-8')
            modified_content = response.content.replace(target_host_bytes, proxy_ip_bytes)

            for key, value in response.headers.items():
                if key.lower() in ['content-encoding', 'transfer-encoding', 'connection', 'content-length']:
                    continue
                
                if key.lower() == 'location':
                    proxy_base = f"https://{CONFIG['PROXY_IP_FOR_REWRITING']}" if CONFIG['SSL_MODE'] else f"http://{CONFIG['PROXY_IP_FOR_REWRITING']}:{CONFIG['PROXY_PORT']}"
                    base_url = f"{proxy_base}{self.path}"
                    modified_value = urljoin(base_url, value).replace(CONFIG['TARGET_HOST'], CONFIG['PROXY_IP_FOR_REWRITING'])
                    self.send_header(key, modified_value)
                elif key.lower() == 'set-cookie':
                    all_cookies = re.split(r',\s*(?=[a-zA-Z0-9_]+=)', value)
                    for cookie_str in all_cookies:
                        cookie_parts = cookie_str.split(';')
                        new_cookie_parts = [part.strip() for part in cookie_parts if 'domain=' not in part.strip().lower()]
                        modified_value = '; '.join(new_cookie_parts)
                        self.send_header('Set-Cookie', modified_value)
                else:
                    self.send_header(key, value)
            
            self.send_header('Content-Length', str(len(modified_content)))
            self.end_headers()
            self.wfile.write(modified_content)

        except requests.exceptions.RequestException as e:
            print(f"Error forwarding request: {e}")
            self.send_error(502, "Bad Gateway: Could not connect to the target server.")

    def do_GET(self): self.do_request('GET')
    def do_POST(self): self.do_request('POST')

def run_server():
    """Starts the server based on the global CONFIG."""
    class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        pass

    address = (CONFIG['PROXY_HOST'], CONFIG['PROXY_PORT'])
    httpd = ThreadedTCPServer(address, WAFRequestHandler)
    
    if CONFIG['SSL_MODE']:
        try:
            httpd.socket = ssl.wrap_socket(
                httpd.socket,
                server_side=True,
                certfile=CONFIG['CERT_FILE'],
                keyfile=CONFIG['KEY_FILE'],
                ssl_version=ssl.PROTOCOL_TLS
            )
            print(f"✅ WAF running in SSL/TLS (HTTPS) mode on port {CONFIG['PROXY_PORT']}")
        except FileNotFoundError:
            print(f"❌ Error: Certificate or key file not found. Please check paths.")
            return
        except Exception as e:
            print(f"❌ SSL Error: {e}")
            return
    else:
        print(f"✅ WAF running in non-SSL (HTTP) mode on port {CONFIG['PROXY_PORT']}")

    print(f"Forwarding to: http://{CONFIG['TARGET_HOST']}:{CONFIG['TARGET_PORT']}")
    print("Press Ctrl+C to stop.")
    httpd.serve_forever()

if __name__ == "__main__":
    print("--- WAF Configuration ---")
    
    # Get protocol choice
    choice = input("Select Protocol:\n1. Non-SSL (HTTP)\n2. SSL/TLS (HTTPS)\nEnter choice (1 or 2): ")
    CONFIG['SSL_MODE'] = (choice == '2')

    # Get IPs and Ports
    CONFIG['TARGET_HOST'] = input("Enter Your Web Server IP (e.g., 10.130): ")
    CONFIG['TARGET_PORT'] = 80 # Assuming backend is always HTTP for simplicity
    CONFIG['PROXY_IP_FOR_REWRITING'] = input("Enter Your WAF Server IP (e.g., 10.129): ")
    CONFIG['PROXY_HOST'] = '0.0.0.0'
    
    if CONFIG['SSL_MODE']:
        CONFIG['PROXY_PORT'] = 443
        CONFIG['CERT_FILE'] = input("Enter path to SSL certificate file (e.g., cert.pem): ")
        CONFIG['KEY_FILE'] = input("Enter path to SSL private key file (e.g., key.pem): ")
    else:
        CONFIG['PROXY_PORT'] = 80

    # Static config
    CONFIG['ERROR_PAGE_FILE'] = "error.html"
    CONFIG['BLOCKED_REQUEST_PATH'] = "/blocked.html"
    
    print("\n--- Starting WAF ---")
    run_server()
