import os
from unittest import result
import requests
import socket
import webbrowser
import threading
import re
import ssl
import subprocess
import urllib.parse
import tkinter as tk
from tkinter import (
    filedialog,
    messagebox,
    scrolledtext,
    Frame,
    Label,
    Button,
    Entry,
    Checkbutton,
    IntVar,
)
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet

import nmap

# ---------- Vulnerability Assessment Functions ----------


def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_remaining = (ssl_expiry - datetime.now(timezone.utc)).days
                score = 10 if days_remaining > 30 else 5 if days_remaining > 7 else 2
                return score, f"SSL certificate valid until: {ssl_expiry.strftime('%Y-%m-%d %H:%M:%S %Z')} ({days_remaining} days remaining)\n"
    except ssl.SSLError as e:
        return 0, f"SSL error: {e}\n"
    except socket.timeout:
        return 0, "Connection timeout. Unable to check SSL certificate.\n"
    except socket.gaierror:
        return 0, "Invalid domain or network issue.\n"
    except Exception as e:
        return 0, f"Unexpected error: {e}\n"


def owasp_zap_scan(url):
    zap_url = (
        "http://localhost:8080"  # Adjust if ZAP is running on a different port
    )
    api_key = "your_zap_api_key"
    try:
        scan_id = requests.get(
            f"{zap_url}/JSON/ascan/action/scan/?apikey={api_key}&url={url}"
        ).json()["scan"]
        while True:
            status = requests.get(
                f"{zap_url}/JSON/ascan/view/status/?apikey={api_key}&scanId={scan_id}"
            ).json()["status"]
            if int(status) >= 100:
                break

        results = requests.get(
            f"{zap_url}/JSON/core/view/alerts/?apikey={api_key}&baseurl={url}"
        ).json()
        alerts = results["alerts"]
        if alerts:
            alert_details = "\n".join(
                [
                    f"- {alert['alert']}: {alert['url']} (Risk Level: {alert['risk']})"
                    for alert in alerts
                ]
            )
            return (
                4,
                f"Security issues detected in the scan:\n{alert_details}\n",
            )
        else:
            return 10, "No security issues detected in the scan.\n"
    except Exception as e:
        return 0, f"Error during OWASP ZAP scan: {e}\n"


def check_sql_injection(url, params=None):
    payloads = [
        "' OR 1=1--", "' OR '1'='1", "' OR 1=1 #", "' OR 1=1 /*", "') OR ('1'='1--", "') OR ('1'='1'--",
        "'; DROP TABLE users--", "' UNION SELECT null, null--", "' UNION SELECT username, password FROM users--",
        "' AND 1=0 UNION SELECT null, version()--", "' AND 1=0 UNION SELECT null, database()--",
        "' AND 1=0 UNION SELECT null, table_name FROM information_schema.tables--",
        "' AND 1=0 UNION SELECT null, column_name FROM information_schema.columns WHERE table_name='users'--",
        "' OR sleep(5)--", "' OR benchmark(1000000, sha1('test'))--"
    ]

    for payload in payloads:
        encoded_payload = urllib.parse.quote(payload)
        
        # GET Request Test
        test_url = f"{url}{encoded_payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200 and any(err in response.text.lower() for err in ["sql", "syntax error", "database error", "query failed"]):
                return 2, f"Possible SQL Injection detected via GET with payload: {payload}\n"
        except requests.exceptions.RequestException:
            continue  # Ignore request errors for GET
        
        # POST Request Test (if params are given)
        if params:
            test_params = {key: payload for key in params}
            try:
                response = requests.post(url, data=test_params, timeout=5)
                if response.status_code == 200 and any(err in response.text.lower() for err in ["sql", "syntax error", "database error", "query failed"]):
                    return 2, f"Possible SQL Injection detected via POST with payload: {payload}\n"
            except requests.exceptions.RequestException:
                continue  # Ignore request errors for POST
    
    return 10, "No SQL Injection vulnerability detected.\n"



def check_xss(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        '"><script>alert("XSS")</script>',
        '" onmouseover="alert(\'XSS\')" "',
    ]
    for payload in payloads:
        test_url = f"{url}?input={payload}"
        try:
            response = requests.get(test_url)
            if payload in response.text:
                return 3, f"Possible XSS vulnerability detected with payload: {payload}\n"
        except Exception as e:
            return 0, f"Error checking XSS vulnerability: {e}\n"
    return 10, "No XSS vulnerability detected.\n"


def check_http_security_headers(url):
    headers_to_check = [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-XSS-Protection",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    missing_headers = []
    try:
        response = requests.get(url)
        headers = response.headers
        for header in headers_to_check:
            if header not in headers:
                missing_headers.append(header)
        if missing_headers:
            return (
                5,
                f"Missing security headers: {', '.join(missing_headers)}\n",
            )
        else:
            return 10, "All required security headers are present.\n"
    except Exception as e:
        return 0, f"Error checking security headers: {e}\n"


def analyze_apk(apk_file):
    try:
        output_dir = "decoded_apk"
        subprocess.run(["apktool", "d", apk_file, "-o", output_dir], check=True)

        manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        permissions = []
        for child in root.iter("uses-permission"):
            permissions.append(
                child.attrib["{http://schemas.android.com/apk/res/android}name"]
            )

        report = f"Analyzing APK: {os.path.basename(apk_file)}\n"
        report += f"Permissions: {permissions}\n"

        risky_permissions = [
            "android.permission.INTERNET",
            "android.permission.READ_EXTERNAL_STORAGE",
        ]
        risks_found = False
        score = 10
        for permission in permissions:
            if permission in risky_permissions:
                report += f"Risky permission detected: {permission}\n"
                risks_found = True
                score -= 5  # Deduct points for risky permissions

        return score, (
            report
            if risks_found
            else report + "No risky permissions detected.\n"
        )
    except Exception as e:
        return 0, f"Error analyzing APK: {e}\n"


def check_open_ports(url):
    try:
        domain = url.split("//")[1].split("/")[0]
        nm = nmap.PortScanner()
        nm.scan(domain, arguments="-sV")
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    if nm[host][proto][port]["state"] == "open":
                        open_ports.append(port)
        if open_ports:
            return 5, f"Open ports detected: {', '.join(map(str, open_ports))}\n"
        else:
            return 10, "No open ports detected.\n"
    except Exception as e:
        return 0, f"Error checking open ports: {e}\n"

def dns_spoofing_test(domain):
    # This function requires actual DNS queries; the example is simplified.
    try:
        # Assume we're checking if the domain resolves to an unexpected IP
        ip_address = socket.gethostbyname(domain)
        # Replace 'expected_ip' with the actual expected IP for the domain
        expected_ip = "192.0.2.1"
        if ip_address != expected_ip:
            return (
                2,
                f"DNS Spoofing risk detected! Resolved IP: {ip_address} (expected: {expected_ip})\n",
            )
        return 10, "No DNS spoofing risk detected.\n"
    except Exception as e:
        return 0, f"Error during DNS spoofing test: {e}\n"


def directory_traversal_test(url):
    test_url = f"{url}/path/to/file?file=../../../etc/passwd"  # Example path
    try:
        response = requests.get(test_url)
        if "root" in response.text:
            return 2, "Possible Directory Traversal vulnerability detected!\n"
        else:
            return 10, "No Directory Traversal vulnerability detected.\n"
    except Exception as e:
        return 0, f"Error checking Directory Traversal: {e}\n"




def remote_code_execution_test(url):
    """
    Checks for potential Remote Code Execution (RCE) vulnerabilities.
    
    It appends common RCE payloads to the URL and inspects the response for execution evidence.
    """
    rce_payloads = [
        "test; ls",  # Unix command injection test
        "test && whoami",  # Logical operator injection
        "$(whoami)",  # Substitution injection
        "`whoami`",  # Backtick injection
        "; echo vulnerable",  # Simple execution check
        "| id",  # Pipe-based execution
    ]

    try:
        for payload in rce_payloads:
            test_url = f"{url}?cmd={payload}"  # Inject payload in 'cmd' parameter
            response = requests.get(test_url, timeout=10)

            # Check for command output in response
            if any(keyword in response.text.lower() for keyword in ["root", "admin", "uid=", "vulnerable"]):
                return 2, f"Potential RCE vulnerability detected with payload: {payload}\n"

        return 10, "No Remote Code Execution vulnerability detected.\n"

    except requests.RequestException as e:
        return 0, f"Error testing for RCE: {e}"




def file_inclusion_test(url):
    test_url = f"{url}/file?file=../../../../etc/passwd"  # Example path
    try:
        response = requests.get(test_url)
        if "root" in response.text:
            return 2, "Possible File Inclusion vulnerability detected!\n"
        else:
            return 10, "No File Inclusion vulnerability detected.\n"
    except Exception as e:
        return 0, f"Error checking File Inclusion: {e}\n"


def check_cors(url):
    try:
        response = requests.options(url)
        if "Access-Control-Allow-Origin" in response.headers:
            return 10, "CORS is properly configured.\n"
        else:
            return 2, "CORS misconfiguration detected!\n"
    except Exception as e:
        return 0, f"Error checking CORS: {e}\n"


def security_misconfiguration_test(url):
    # Placeholder for security misconfiguration checks.
    return 10, "No security misconfigurations detected.\n"


def insecure_cryptographic_storage_test(url):
    # Placeholder for checking insecure cryptographic storage.
    return 10, "No insecure cryptographic storage detected.\n"


def sensitive_data_exposure_test(url):
    # Placeholder for checking sensitive data exposure.
    return 10, "No sensitive data exposure detected.\n"


def check_security_updates(url):
    # Placeholder for checking for missing security updates.
    return 10, "All security updates are applied.\n"


def ssrf_test(url):
    # Placeholder for SSRF checks.
    return 10, "No SSRF vulnerabilities detected.\n"


def clickjacking_test(url):
    try:
        response = requests.get(url)
        if "X-Frame-Options" in response.headers:
            return 10, "No Clickjacking vulnerabilities detected.\n"
        else:
            return 2, "Clickjacking risk detected!\n"
    except Exception as e:
        return 0, f"Error checking Clickjacking: {e}\n"


def info_disclosure_test(url):
    try:
        response = requests.get(url)
        if response.status_code >= 400:
            return (
                2,
                f"Information disclosure detected! Status code: {response.status_code}\n",
            )
        return 10, "No information disclosure detected.\n"
    except Exception as e:
        return 0, f"Error checking Information Disclosure: {e}\n"




def email_header_injection_test(url):
    """
    Tests for email header injection vulnerabilities by sending a malicious payload.
    """
    payload = {
        "email": "test@example.com\r\nCC: victim@example.com"
    }

    try:
        response = requests.post(url, data=payload)
        if "CC: victim@example.com" in response.text:
            return 2, "Email header injection vulnerability detected!\n"
        return 10, "No email header injection vulnerabilities detected.\n"
    
    except Exception as e:
        return 0, f"Error checking email header injection: {e}\n"



def command_injection_test(url):
    """
    Tests for command injection vulnerabilities by sending a suspicious payload.
    """
    payload = {"input": "; ls"}
    try:
        response = requests.post(url, data=payload)
        if "bin" in response.text or "root" in response.text:
            return 2, "Command injection vulnerability detected!\n"
        return 10, "No command injection vulnerabilities detected.\n"
    except Exception as e:
        return 0, f"Error checking command injection: {e}\n"


def improper_authentication_test(url):
    """
    Checks if authentication can be bypassed using default credentials.
    """
    payload = {"username": "admin", "password": "admin"}
    try:
        response = requests.post(url, data=payload)
        if "Welcome" in response.text:
            return 2, "Improper authentication detected!\n"
        return 10, "No improper authentication detected.\n"
    except Exception as e:
        return 0, f"Error checking authentication: {e}\n"


def insecure_api_endpoints_test(url):
    """
    Checks for open API endpoints that return sensitive data.
    """
    try:
        response = requests.get(f"{url}/api/v1/users")
        if response.status_code == 200 and "password" in response.text:
            return 2, "Insecure API endpoint detected!\n"
        return 10, "No insecure API endpoints detected.\n"
    except Exception as e:
        return 0, f"Error checking API endpoints: {e}\n"


def unrestricted_file_upload_test(url):
    """
    Tests if a server allows unrestricted file uploads.
    """
    files = {'file': ('test.php', b'<?php echo "Vulnerable"; ?>', 'application/x-php')}
    try:
        response = requests.post(url, files=files)
        if response.status_code == 200:
            return 2, "Unrestricted file upload vulnerability detected!\n"
        return 10, "No unrestricted file upload vulnerabilities detected.\n"
    except Exception as e:
        return 0, f"Error checking file upload: {e}\n"


def weak_password_policy_test(url):
    """
    Checks if a weak password is accepted during registration.
    """
    payload = {"username": "testuser", "password": "123"}
    try:
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            return 2, "Weak password policy detected!\n"
        return 10, "Password policy is strong.\n"
    except Exception as e:
        return 0, f"Error checking password policy: {e}\n"

def no_rate_limiting_test(url):
    """
    Checks if rate limiting is implemented by sending multiple requests.
    """
    try:
        for _ in range(5):
            response = requests.get(url)
            if response.status_code != 200:
                return 10, "Rate limiting is implemented.\n"
        return 2, "No rate limiting detected!\n"
    except Exception as e:
        return 0, f"Error checking rate limiting: {e}\n"


def missing_https_redirection_test(url):
    """
    Checks if HTTP requests are properly redirected to HTTPS.
    """
    try:
        response = requests.get(url.replace("https://", "http://"), allow_redirects=False)
        if response.status_code == 200:
            return 2, "Missing HTTPS redirection!\n"
        return 10, "HTTPS redirection is properly configured.\n"
    except Exception as e:
        return 0, f"Error checking HTTPS redirection: {e}\n"





def insecure_session_management_test(url):
    """
    Tests for insecure session management vulnerabilities.
    """
    try:
        session = requests.Session()
        response = session.get(url)

        # Extract cookies
        cookies = response.cookies
        insecure_cookies = []
        
        for cookie in cookies:
            if not cookie.secure:
                insecure_cookies.append(f"Cookie '{cookie.name}' is not marked as Secure.")
            if not cookie.has_nonstandard_attr("httponly"):
                insecure_cookies.append(f"Cookie '{cookie.name}' is not marked as HttpOnly.")

        # Check if session tokens are in the URL (bad practice)
        if "sessionid=" in url or "token=" in url:
            insecure_cookies.append("Session ID or token found in URL. This is insecure!")

        # Determine security score
        if insecure_cookies:
            score = 3  # Low score if insecure practices are found
            details = "Insecure session management detected:\n" + "\n".join(insecure_cookies)
        else:
            score = 10  # Perfect score if no issues
            details = "Session management appears secure.\n"

        return score, details

    except Exception as e:
        return 0, f"Error checking insecure session management: {e}\n"



def outdated_libraries_test(url):
    """
    Checks for outdated JavaScript libraries in the webpage source.
    """
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return 0, f"Failed to retrieve page. HTTP {response.status_code}\n"

        # Example regex to detect common JS libraries & versions
        outdated_libs = []
        library_patterns = {
            "jQuery": r"jquery-([0-9]+\.[0-9]+\.[0-9]+)\.js",
            "Bootstrap": r"bootstrap-([0-9]+\.[0-9]+\.[0-9]+)\.js",
            "AngularJS": r"angular-([0-9]+\.[0-9]+\.[0-9]+)\.js"
        }

        for lib, pattern in library_patterns.items():
            match = re.search(pattern, response.text, re.IGNORECASE)
            if match:
                version = match.group(1)
                outdated_libs.append(f"{lib} version {version} detected. Check for updates.")

        if outdated_libs:
            score = 5
            details = "Outdated libraries detected:\n" + "\n".join(outdated_libs)
        else:
            score = 10
            details = "No outdated libraries detected."

        return score, details

    except Exception as e:
        return 0, f"Error checking outdated libraries: {e}\n"


def broken_access_control_test(url):
    """
    Checks for broken access control by attempting unauthorized access to admin pages.
    """
    try:
        # Common admin URLs to test
        admin_urls = ["/admin", "/dashboard", "/user/settings", "/config"]

        for path in admin_urls:
            test_url = url.rstrip("/") + path
            response = requests.get(test_url)

            if response.status_code == 200:
                return 3, f"Possible broken access control: {test_url} is accessible without authentication!"

        return 10, "Access controls are properly configured."

    except Exception as e:
        return 0, f"Error checking broken access control: {e}\n"


def unencrypted_sensitive_data_test(url):
    """
    Checks if the website forces HTTPS for secure data transmission.
    """
    try:
        if url.startswith("http://"):
            return 2, "Website does not enforce HTTPS. Sensitive data might be exposed!"

        return 10, "Website uses HTTPS, ensuring encrypted data transmission."

    except Exception as e:
        return 0, f"Error checking unencrypted sensitive data: {e}\n"



def weak_ssl_tls_config_test(url):
    """
    Checks if SSL/TLS settings are weak.
    """
    try:
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            return 2, "Weak SSL/TLS configuration detected!\n"
        return 10, "SSL/TLS configuration is secure.\n"
    except Exception as e:
        return 0, f"Error checking SSL/TLS: {e}\n"


def subdomain_takeover_test(url):
    """
    Tests for subdomain takeover vulnerabilities by sending a request to check for misconfigurations.
    """
    try:
        response = requests.get(url)
        if "404 Not Found" in response.text or "This domain is available" in response.text:
            return 2, "Subdomain takeover vulnerability detected!\n"
        return 10, "No subdomain takeover vulnerabilities detected.\n"
    except Exception as e:
        return 0, f"Error checking subdomain takeover: {e}\n"


def missing_csp_test(url):
    """
    Tests for the presence of a Content Security Policy (CSP) header.
    """
    try:
        response = requests.get(url)
        if "Content-Security-Policy" not in response.headers:
            return 2, "Missing CSP header detected!\n"
        return 10, "CSP is properly configured.\n"
    except Exception as e:
        return 0, f"Error checking CSP: {e}\n"


def lack_of_privacy_policy_test(url):
    """
    Checks if the website has a privacy policy.
    """
    try:
        response = requests.get(f"{url}/privacy-policy")
        if response.status_code == 404:
            return 2, "Privacy policy is missing!\n"
        return 10, "Privacy policy is present.\n"
    except Exception as e:
        return 0, f"Error checking privacy policy: {e}\n"


def unnecessary_services_test(url):
    """
    Checks for unnecessary services running on the server.
    """
    try:
        response = requests.get(url)
        if "FTP" in response.text or "Telnet" in response.text:
            return 2, "Unnecessary services detected!\n"
        return 10, "No unnecessary services running.\n"
    except Exception as e:
        return 0, f"Error checking unnecessary services: {e}\n"


def session_fixation_test(url):
    """
    Tests for session fixation vulnerabilities.
    """
    try:
        response = requests.get(url)
        if "Set-Cookie" in response.headers and "sessionid" in response.headers["Set-Cookie"]:
            return 2, "Session fixation vulnerability detected!\n"
        return 10, "No session fixation vulnerabilities detected.\n"
    except Exception as e:
        return 0, f"Error checking session fixation: {e}\n"


def client_side_security_issues_test(url):
    """
    Checks for common client-side security issues.
    """
    try:
        response = requests.get(url)
        if "<script>alert('XSS')</script>" in response.text:
            return 2, "Client-side security vulnerabilities detected!\n"
        return 10, "Client-side security is strong.\n"
    except Exception as e:
        return 0, f"Error checking client-side security: {e}\n"


def social_engineering_vulnerabilities_test(url):
    """
    Checks for possible social engineering vulnerabilities.
    """
    try:
        response = requests.get(url)
        if "win a free iPhone" in response.text.lower():
            return 2, "Social engineering vulnerabilities detected!\n"
        return 10, "No significant social engineering vulnerabilities detected.\n"
    except Exception as e:
        return 0, f"Error checking social engineering vulnerabilities: {e}\n"


def csrf_test(url):
    """
    Tests for CSRF vulnerabilities by checking for CSRF tokens.
    """
    try:
        response = requests.get(url)
        if "csrf_token" not in response.text:
            return 2, "CSRF vulnerability detected!\n"
        return 10, "No CSRF vulnerabilities detected.\n"
    except Exception as e:
        return 0, f"Error checking CSRF: {e}\n"


def missing_referrer_policy_test(url):
    """
    Tests for the presence of a referrer policy header.
    """
    try:
        response = requests.get(url)
        if "Referrer-Policy" not in response.headers:
            return 2, "Missing referrer policy detected!\n"
        return 10, "Referrer policy is configured.\n"
    except Exception as e:
        return 0, f"Error checking referrer policy: {e}\n"


def insecure_js_libs_test(url):
    """
    Checks for outdated or insecure JavaScript libraries.
    """
    try:
        response = requests.get(url)
        if "jquery-1.4.1.js" in response.text:
            return 2, "Insecure JavaScript libraries detected!\n"
        return 10, "No insecure JS libraries detected.\n"
    except Exception as e:
        return 0, f"Error checking JS libraries: {e}\n"



def directory_indexing_test(url):
    test_url = f"{url}/"
    try:
        response = requests.get(test_url)
        if response.status_code == 200 and "Index of" in response.text:
            return 2, "Directory indexing is enabled!\n"
        else:
            return 10, "Directory indexing is disabled.\n"
    except Exception as e:
        return 0, f"Error checking Directory Indexing: {e}\n"


def overly_verbose_error_messages_test(url):
    test_url = f"{url}/invalid_endpoint"
    try:
        response = requests.get(test_url)
        if response.status_code >= 400:
            return (
                2,
                f"Verbose error message detected! Status code: {response.status_code}\n",
            )
        return 10, "No overly verbose error messages detected.\n"
    except Exception as e:
        return 0, f"Error checking verbose error messages: {e}\n"


def weak_input_validation_test(url):
    test_url = f"{url}/input?value=<script>alert('xss')</script>"
    try:
        response = requests.get(test_url)
        if "<script>alert('xss')</script>" in response.text:
            return 2, "Weak input validation detected!\n"
        return 10, "Input validation is strong.\n"
    except Exception as e:
        return 0, f"Error checking input validation: {e}\n"


def cookie_security_flags_test(url):
    try:
        response = requests.get(url)
        if "Set-Cookie" in response.headers:
            cookies = response.headers["Set-Cookie"]
            if "HttpOnly" in cookies and "Secure" in cookies:
                return 10, "Cookie security flags are set correctly.\n"
            else:                return 2, "Cookie security flags are missing!\n"
        return 10, "No cookies set, secure by default.\n"
    except Exception as e:
        return 0, f"Error checking cookie security flags: {e}\n"



import re

def using_deprecated_apis_test(url):
    """
    Scans a webpage for potential usage of deprecated JavaScript APIs.
    """
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return 2, f"Unable to access page. Status Code: {response.status_code}\n"

        deprecated_apis = [
            "document.write", "escape", "unescape", "showModalDialog", "XMLHttpRequest", 
            "navigator.appVersion", "navigator.userAgent"
        ]
        
        found = [api for api in deprecated_apis if re.search(rf"\b{api}\b", response.text)]

        if found:
            return 2, f"Deprecated APIs detected: {', '.join(found)}\n"
        
        return 10, "No deprecated APIs detected.\n"

    except Exception as e:
        return 0, f"Error checking deprecated APIs: {e}\n"



def client_side_caching_issues_test(url):
    """
    Checks if caching policies are properly implemented via HTTP headers.
    """
    try:
        response = requests.get(url)
        cache_headers = ["Cache-Control", "Pragma", "Expires"]
        missing_headers = [header for header in cache_headers if header not in response.headers]

        if missing_headers:
            return 2, f"Potential caching issues: Missing headers - {', '.join(missing_headers)}\n"

        return 10, "Client-side caching is secure.\n"

    except Exception as e:
        return 0, f"Error checking client-side caching: {e}\n"



def lack_of_two_factor_authentication_test(url):
    """
    Checks if the login page mentions or supports Two-Factor Authentication (2FA).
    """
    try:
        response = requests.get(url)
        if "2FA" in response.text or "Two-Factor Authentication" in response.text or "OTP" in response.text:
            return 10, "Two-Factor Authentication is implemented.\n"

        return 2, "No mention of Two-Factor Authentication detected.\n"

    except Exception as e:
        return 0, f"Error checking for 2FA implementation: {e}\n"





# def broken_link_checking_test(url):
#     """
#     Checks for broken links on the given webpage by analyzing all anchor tags.
#     """
#     try:
#         response = requests.get(url)
#         if response.status_code != 200:
#             return 2, f"Unable to access page. Status Code: {response.status_code}\n"

#         soup = BeautifulSoup(response.text, "html.parser")
#         links = [urljoin(url, a.get("href")) for a in soup.find_all("a", href=True)]
        
#         broken_links = []
#         for link in links:
#             try:
#                 link_response = requests.head(link, allow_redirects=True, timeout=5)
#                 if link_response.status_code >= 400:
#                     broken_links.append(link)
#             except requests.RequestException:
#                 broken_links.append(link)

#         if broken_links:
#             return 2, f"Broken links detected:\n" + "\n".join(broken_links) + "\n"

#         return 10, "No broken links detected.\n"

#     except Exception as e:
#         return 0, f"Error checking for broken links: {e}\n"






def sensitive_info_in_code_repositories_test(url):
    """
    Checks for potential exposure of sensitive information in public code repositories like GitHub, GitLab, or Bitbucket.
    """
    try:
        # Common repository paths that might be exposed
        repo_paths = [
            ".git/config", ".gitignore", ".env", "config.yml", "secrets.json",
            "docker-compose.yml", "package-lock.json", "composer.lock"
        ]

        for path in repo_paths:
            test_url = f"{url}/{path}"
            response = requests.get(test_url)

            # If the file exists and contains sensitive patterns, flag it
            if response.status_code == 200 and len(response.text) > 10:
                return 2, f"Potential sensitive information exposure detected: {test_url}\n"

        return 10, "No sensitive information found in code repositories.\n"

    except Exception as e:
        return 0, f"Error checking sensitive information in code repositories: {e}\n"






def open_redirects_test(url):
    """
    Checks for potential open redirect vulnerabilities by appending common payloads.
    """
    try:
        payloads = [
            "http://evil.com", 
            "//evil.com", 
            "/\\evil.com", 
            "https://google.com"
        ]
        
        for payload in payloads:
            test_url = f"{url}?redirect={payload}"  # Inject payload into a common redirect parameter
            response = requests.get(test_url, allow_redirects=True)

            # If the final URL in response is the payload domain, it's vulnerable
            if any(evil in response.url for evil in ["evil.com", "google.com"]):
                return 2, f"Potential open redirect detected with payload: {payload}\n"

        return 10, "No open redirect vulnerabilities detected.\n"

    except Exception as e:
        return 0, f"Error checking open redirects: {e}\n"







def memory_leak_vulnerabilities_test(url):
    """
    Checks for potential memory leak vulnerabilities by analyzing response headers and content.
    """
    try:
        response = requests.get(url)

        # Check for known memory leak indicators in the response
        leak_keywords = ["OutOfMemoryError", "heap dump", "memory leak", "Fatal error", "Segmentation fault"]

        if any(keyword in response.text for keyword in leak_keywords):
            return 3, "Potential memory leak detected in response!\n"
        
        return 10, "No memory leaks detected.\n"

    except Exception as e:
        return 0, f"Error checking memory leaks: {e}\n"





def check_clickjacking_protections(url):
    try:
        response = requests.get(url)
        if "X-Frame-Options" in response.headers:
            return 10, "Clickjacking protections are in place.\n"
        else:
            return 2, "Clickjacking protections are missing!\n"
    except Exception as e:
        return 0, f"Error checking clickjacking protections: {e}\n"




def evaluate_third_party_dependencies_test(url):
    try:
        # Send a request to the website
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an error for bad responses (4xx, 5xx)

        # Parse HTML content
        soup = BeautifulSoup(response.text, "html.parser")

        # Find all script tags
        scripts = soup.find_all("script", src=True)

        third_party_scripts = []

        for script in scripts:
            src = script["src"]
            full_url = urljoin(url, src)  # Convert relative URLs to absolute URLs
            
            # Check if it's a third-party script (not from the same domain)
            if not src.startswith("/") and url not in src:
                third_party_scripts.append(full_url)

        if third_party_scripts:
            details = "Third-party dependencies found:\n" + "\n".join(third_party_scripts)
            return 5, details  # Lower score due to third-party dependencies
        else:
            return 10, "No third-party dependencies found."

    except requests.RequestException as e:
        return 0, f"Error fetching the webpage: {e}"




def check_directory_listing(url):
    test_url = f"{url}/"
    try:
        response = requests.get(test_url)
        if response.status_code == 200 and "Index of" in response.text:
            return 2, "Directory listing is enabled!\n"
        else:
            return 10, "Directory listing is disabled.\n"
    except Exception as e:
        return 0, f"Error checking directory listing: {e}\n"


def check_sensitive_files(url):
    sensitive_files = [
        "config.php",
        "admin.php",
        "database.sql",
        "backup.zip",
        # Add more sensitive file names
    ]
    exposed_files = []
    for file in sensitive_files:
        test_url = f"{url}/{file}"
        try:
            response = requests.get(test_url)
            if response.status_code == 200:
                exposed_files.append(file)
        except:
            pass
    if exposed_files:
        return 2, f"Sensitive files exposed: {', '.join(exposed_files)}\n"
    else:
        return 10, "No sensitive files found.\n"


# ---------- PDF Report Generation ----------



from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from datetime import datetime

def add_footer(canvas, doc):
    """
    Adds footer with page number and date.
    """
    canvas.saveState()
    footer_text = f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    canvas.setFont("Helvetica", 9)
    canvas.drawString(30, 20, footer_text)
    canvas.drawString(500, 20, f"Page {doc.page}")
    canvas.restoreState()

def generate_pie_chart(results):
    """
    Generate a pie chart based on risk levels.
    """
    risk_counts = {"Low": 0, "Medium": 0, "High": 0}
    for _, (score, _) in results.items():
        if score < 4:
            risk_counts["Low"] += 1
        elif score < 7:
            risk_counts["Medium"] += 1
        else:
            risk_counts["High"] += 1
    
    drawing = Drawing(400, 200)
    pie = Pie()
    pie.x = 50
    pie.y = 30
    pie.width = 300
    pie.height = 150
    pie.data = list(risk_counts.values())
    pie.labels = list(risk_counts.keys())
    pie.slices[0].fillColor = colors.green  # Low risk
    pie.slices[1].fillColor = colors.orange  # Medium risk
    pie.slices[2].fillColor = colors.red  # High risk
    drawing.add(pie)
    return drawing

def generate_report(results):
    pdf_filename = "vulnerability_report.pdf"
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle(
        "Title", parent=styles["Title"], fontSize=24, spaceAfter=20,
        textColor=colors.darkblue, alignment=1
    )
    heading_style = ParagraphStyle(
        "Heading2", parent=styles["Heading2"], fontSize=16, spaceAfter=10, textColor=colors.darkred
    )
    normal_style = ParagraphStyle(
        "Normal", parent=styles["Normal"], fontSize=12, spaceAfter=10, leading=15
    )
    
    elements = []
    
    # Cover Page
    elements.append(Paragraph("Vulnerability Assessment Report", title_style))
    elements.append(Spacer(1, 50))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Spacer(1, 300))
    elements.append(Paragraph("Prepared by: Security Audit Team", normal_style))
    elements.append(PageBreak())
    
    # Summary Table
    elements.append(Paragraph("Summary of Findings", heading_style))
    elements.append(Spacer(1, 10))
    
    summary_data = [["Test Name", "Score"]]
    for test, (score, _) in results.items():
        summary_data.append([test, f"{score}/10"])
    
    summary_table = Table(summary_data, colWidths=[350, 100])
    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTSIZE", (0, 0), (-1, 0), 14),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ])
    )
    elements.append(summary_table)
    elements.append(Spacer(1, 20))
    
    # Add Pie Chart
    elements.append(Paragraph("Risk Level Distribution", heading_style))
    elements.append(Spacer(1, 10))
    elements.append(generate_pie_chart(results))
    elements.append(PageBreak())
    
    # Detailed Test Results
    elements.append(Paragraph("Detailed Test Results", heading_style))
    elements.append(Spacer(1, 10))
    for test, (score, details) in results.items():
        elements.append(Paragraph(f"{test} - Score: <b>{score}/10</b>", heading_style))
        elements.append(Paragraph(f"<b>Details:</b> {details}", normal_style))
        elements.append(Spacer(1, 12))
    
    # Build PDF with Footer
    doc.build(elements, onLaterPages=add_footer, onFirstPage=add_footer)
    return pdf_filename

# ---------- GUI Application ----------


class VulnerabilityAssessmentTool:
    def __init__(self, master):
        self.master = master
        master.title("Vulnerability Assessment Tool")

        self.url_label = Label(master, text="Enter URL:")
        self.url_label.pack()

        self.url_entry = Entry(master)
        self.url_entry.pack()

        self.apk_label = Label(master, text="Select APK File:")
        self.apk_label.pack()

        self.apk_entry = Entry(master)
        self.apk_entry.pack()

        self.apk_button = Button(master, text="Browse", command=self.browse_apk)
        self.apk_button.pack()

        self.run_button = Button(
            master, text="Run Assessment", command=self.start_assessment
        )
        self.run_button.pack()

        self.doc_button = Button(master, text="Open Documentation", command=self.open_documentation)
        self.doc_button.place(relx=1.0, y=10, anchor="ne")  # Position at top-right


        self.results_text = scrolledtext.ScrolledText(master, width=100, height=30)
        self.results_text.pack()

    def browse_apk(self):
        apk_file = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk")])
        self.apk_entry.delete(0, tk.END)
        self.apk_entry.insert(0, apk_file)
    def open_documentation(self):
        """Opens the documentation PDF."""
        pdf_path = os.path.abspath("Vulnerability_Assessment_Documentation.pdf")  # Make sure the PDF is in the same folder
        if os.path.exists(pdf_path):
            webbrowser.open(pdf_path)
        else:
            self.results_text.insert(tk.END, "Documentation file not found!\n")

    def start_assessment(self):
        """Starts the assessment in a separate thread."""
        assessment_thread = threading.Thread(target=self.run_assessment, daemon=True)
        assessment_thread.start()

    def run_assessment(self):
        """Runs the vulnerability tests in a separate thread to keep the GUI responsive."""
        url = self.url_entry.get()
        apk_file = self.apk_entry.get()
        results = {}

        self.results_text.delete(1.0, tk.END)  # Clear previous results

        # Run all tests
        tests = [
            ("SSL Certificate Check", check_ssl_certificate),
            ("OWASP ZAP Scan", owasp_zap_scan),
            ("SQL Injection Test", check_sql_injection),
            ("Cross-Site Scripting (XSS) Test", check_xss),
            ("HTTP Security Headers Test", check_http_security_headers),
            ("Directory Listing Test", check_directory_listing),
            ("Sensitive Files Test", check_sensitive_files),
            ("Open Ports Test", check_open_ports),
            ("Check SSL Certificate", check_ssl_certificate),
            ("OWASP ZAP Scan", owasp_zap_scan),
            ("SQL Injection Test", check_sql_injection),
            ("XSS Test", check_xss),
            ("HTTP Security Headers Test", check_http_security_headers),
            ("APK Analysis", analyze_apk),
            ("Information Disclosure Test", info_disclosure_test),
            ("Email Header Injection Test", email_header_injection_test),
            ("Command Injection Test", command_injection_test),
            ("Improper Authentication Test", improper_authentication_test),
            ("Insecure API Endpoints Test", insecure_api_endpoints_test),
            ("Unrestricted File Upload Test", unrestricted_file_upload_test),
            ("Weak Password Policy Test", weak_password_policy_test),
            
            ("No Rate Limiting Test", no_rate_limiting_test),
            ("Missing HTTPS Redirection Test", missing_https_redirection_test),
            ("Insecure Session Management Test", insecure_session_management_test),
            ("Outdated Libraries Test", outdated_libraries_test),
            ("Broken Access Control Test", broken_access_control_test),
            ("Unencrypted Sensitive Data Test", unencrypted_sensitive_data_test),
            ("Weak SSL/TLS Configuration Test", weak_ssl_tls_config_test),
            ("Subdomain Takeover Test", subdomain_takeover_test),
            ("Missing CSP Test", missing_csp_test),
            ("Lack of Privacy Policy Test", lack_of_privacy_policy_test),
            ("Unnecessary Services Test", unnecessary_services_test),
            ("Session Fixation Test", session_fixation_test),
            ("Client-Side Security Issues Test", client_side_security_issues_test),
            ("Social Engineering Vulnerabilities Test", social_engineering_vulnerabilities_test),
            ("CSRF Test", csrf_test),
            ("Missing Referrer Policy Test", missing_referrer_policy_test),
            ("Insecure JS Libraries Test", insecure_js_libs_test),
            ("Directory Indexing Test", directory_indexing_test),
            ("Overly Verbose Error Messages Test", overly_verbose_error_messages_test),
            ("Weak Input Validation Test", weak_input_validation_test),
            ("Cookie Security Flags Test", cookie_security_flags_test),
            ("Using Deprecated APIs Test", using_deprecated_apis_test),
            ("Client-Side Caching Issues Test", client_side_caching_issues_test),
            ("Lack of Two-Factor Authentication Test", lack_of_two_factor_authentication_test),
            # ("Broken Link Checking Test", broken_link_checking_test),
            ("Sensitive Info in Code Repositories Test", sensitive_info_in_code_repositories_test),
            ("Open Redirects Test", open_redirects_test),
            ("Memory Leak Vulnerabilities Test", memory_leak_vulnerabilities_test),
            ("Check Clickjacking Protections", check_clickjacking_protections),
            ("Evaluate Third Party Dependencies Test", evaluate_third_party_dependencies_test),
            
        ]

        # Perform assessments
        if url:
            for test_name, test_func in tests:
                self.results_text.insert(tk.END, f"Running {test_name}...\n")
                self.master.update_idletasks()  # Refresh GUI while running tests
                score, detail = test_func(url)
                results[test_name] = (score, detail)
                self.results_text.insert(tk.END, f"{test_name}: Score: {score}\n{detail}\n")

        # Perform APK Analysis
        if apk_file:
            self.results_text.insert(tk.END, "Running APK Analysis...\n")
            self.master.update_idletasks()
            score, apk_report = analyze_apk(apk_file)
            results["APK Analysis"] = (score, apk_report)
            self.results_text.insert(tk.END, f"APK Analysis: Score: {score}\n{apk_report}\n")

        # Generate Report
        pdf_filename = generate_report(results)

        if pdf_filename:
            self.results_text.insert(tk.END, f"\nPDF report generated: {pdf_filename}\n")
        else:
            self.results_text.insert(tk.END, "\nPDF report generation failed.\n")




def generate_report(results):
    # Hide root window
    root = tk.Tk()
    root.withdraw()

    # Prompt user for the file location to save the report
    pdf_filename = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
        title="Save PDF Report"
    )

    if not pdf_filename:  # If user cancels the dialog
        return None

    try:
        doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
        styles = getSampleStyleSheet()

        elements = []
        elements.append(Paragraph("Vulnerability Assessment Report", styles["Title"]))
        elements.append(Spacer(1, 12))

        # Summary Table
        summary_data = [["Test Name", "Score"]]
        for test, (score, details) in results.items():
            summary_data.append([test, score])

        summary_table = Table(summary_data, colWidths=[300, 100])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTSIZE", (0, 0), (-1, 0), 14),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ]
            )
        )

        elements.append(summary_table)
        elements.append(Spacer(1, 20))

        # Detailed Test Results
        for test, (score, details) in results.items():
            elements.append(Paragraph(f"{test} - Score: <b>{score}</b>", styles["Heading2"]))
            elements.append(Paragraph(f"<b>Details:</b> {details}", styles["Normal"]))
            elements.append(Spacer(1, 12))

        doc.build(elements)
        return pdf_filename  # Return the filename of the generated PDF

    except Exception as e:
        print(f"Error generating report: {e}")
        return None


if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityAssessmentTool(root)
    root.mainloop()