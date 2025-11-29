import streamlit as st
import pandas as pd
import re
import socket
import whois
import requests
import time
import json
import os
from passlib.hash import bcrypt
import random
import string
from fpdf import FPDF
from datetime import datetime
import pytz
import hashlib
from io import BytesIO
import base64
from PIL import Image
import qrcode
import pydeck as pdk
import subprocess
import folium
from streamlit_folium import folium_static
from geopy.geocoders import Nominatim
import sys # Import sys to check OS for traceroute command

# --- Configuration ---
class Config:
    TOR_PROXY = {
        'http': 'socks5h://127.0.0.1:9150',
        'https': 'socks5h://127.0.0.1:9150'
    }
    USER_FILE = "users.json"
    SESSION_TIMEOUT = 1800
    ADB_PATH = r"C:\Users\manpr\Downloads\platform-tools-latest-windows\platform-tools\adb.exe"
    THREAT_PATTERNS = {
        "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "IP Address": r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
        "Credit Card": r"\b(?:(?:\d{4}[- ]?){3}\d{4}|\d{13,19})\b",
        "Bitcoin Wallet": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        "Leak Signature": r"id\s*,\s*password\s*,\s*email|CREATE TABLE|INSERT INTO|BEGIN PGP MESSAGE|SELECT \* FROM",
        "JWT/Token": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "Malicious URL": r"(?:https?://|www\.)[^\s/$.?#].[^\s]*\.(?:onion|xyz|top|gq|ml|tk|ru|cn)[^\s]*",
        "SSH Key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
        "Base64 Encoded Data": r"(?:[A-Za-z0-9+/]{4}){1,}(?:[A-Za-z0-9+/]{2}=|[A-Za-z0-9+/]{3}=)?", # Generic base64
        "PowerShell Command": r"powershell\.exe\s+-\s*EncodedCommand", # Common for encoded commands
        "Registry Modification": r"(?:reg\s+add|regedit\s+/s)", # Common registry commands
        "Process Injection": r"(?:CreateRemoteThread|NtCreateThreadEx|QueueUserAPC)", # Common Windows API for injection
        "Obfuscated Script": r"(?:eval\(|exec\(|fromCharCode|String\.prototype\.replace)", # Common JS/VBScript obfuscation
        "Crypto Miner Indicators": r"(?:miner|xmr|monero|cpu-usage:\s*\d{2,3}%)", # Simple indicators
        "Unusual Protocol": r"(?:IRC|FTP|SMB|Telnet|RDP)\s+connection" # New: Detects mentions of unusual protocols
    }
    IPINFO_TOKEN = "63b69b215f168c"

# --- Session State Management ---
class SessionState:
    @staticmethod
    def initialize():
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
        if 'username' not in st.session_state:
            st.session_state.username = None
        if 'page' not in st.session_state:
            st.session_state.page = 'login'
        if 'report_results' not in st.session_state:
            st.session_state.report_results = []
        if 'last_activity' not in st.session_state:
            st.session_state.last_activity = time.time()
        if 'darkweb_cache' not in st.session_state:
            st.session_state.darkweb_cache = {}
        if 'tor_status' not in st.session_state:
            st.session_state.tor_status = False
        if 'adb_devices' not in st.session_state:
            st.session_state.adb_devices = ([], False)
        if 'logs_pulled' not in st.session_state:
            st.session_state.logs_pulled = False
        if 'network_data' not in st.session_state:
            st.session_state.network_data = {}
        if 'locations_data' not in st.session_state:
            st.session_state.locations_data = []
        # Initialize KNOWN_MALICIOUS_HASHES in session state for dynamic updates
        if 'known_malicious_hashes' not in st.session_state:
            st.session_state.known_malicious_hashes = MalwareScanner.INITIAL_MALICIOUS_HASHES.copy()
        if 'traceroute_hops' not in st.session_state:
            st.session_state.traceroute_hops = []
        if 'port_scan_results' not in st.session_state:
            st.session_state.port_scan_results = []


    @staticmethod
    def check_timeout():
        if st.session_state.authenticated and (time.time() - st.session_state.last_activity) > Config.SESSION_TIMEOUT:
            SessionState.logout()
            st.warning("Session timed out due to inactivity. Please log in again.")
            st.rerun()

    @staticmethod
    def update_activity():
        st.session_state.last_activity = time.time()

    @staticmethod
    def logout():
        st.session_state.authenticated = False
        st.session_state.username = None
        st.session_state.page = 'login'
        st.session_state.report_results = []
        st.session_state.darkweb_cache = {}
        st.session_state.locations_data = []
        # Reset hashes to initial state on logout
        st.session_state.known_malicious_hashes = MalwareScanner.INITIAL_MALICIOUS_HASHES.copy()
        st.session_state.traceroute_hops = []
        st.session_state.port_scan_results = []


# --- User Management ---
class UserManager:
    @staticmethod
    def load_users():
        if os.path.exists(Config.USER_FILE):
            try:
                with open(Config.USER_FILE, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                st.error(f"Error loading user data: {e}")
                return {}
        return {}

    @staticmethod
    def save_users(users):
        try:
            with open(Config.USER_FILE, 'w') as f:
                json.dump(users, f, indent=4, ensure_ascii=False)
        except IOError as e:
            st.error(f"Error saving user data: {e}")

    @staticmethod
    def register_user(username, password, email):
        if not username or not password or not email:
            return False, "All fields are required."
        users = UserManager.load_users()
        if username in users:
            return False, "Username already exists."
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return False, "Invalid email format."
        if len(password) < 8:
            return False, "Password must be at least 8 characters."
        users[username] = {
            'password': bcrypt.hash(password),
            'email': email,
            'registration_date': datetime.now(pytz.utc).isoformat()
        }
        UserManager.save_users(users)
        return True, "Registration successful."

    @staticmethod
    def verify_user(username, password):
        users = UserManager.load_users()
        if username in users and bcrypt.verify(password, users[username]['password']):
            return True
        return False

    @staticmethod
    def reset_password(username):
        users = UserManager.load_users()
        if username in users:
            temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            users[username]['password'] = bcrypt.hash(temp_password)
            users[username]['password_reset'] = True
            UserManager.save_users(users)
            return True, temp_password, users[username]['email']
        return False, "Username not found.", None

# --- Security Utilities ---
class SecurityUtils:
    @staticmethod
    def test_tor_connection():
        try:
            session = requests.Session()
            session.proxies = Config.TOR_PROXY
            response = session.get('http://check.torproject.org', timeout=15)
            response.raise_for_status()
            if "Congratulations" in response.text:
                st.session_state.tor_status = True
                return True
            st.session_state.tor_status = False
            return False
        except requests.exceptions.ConnectionError:
            st.error("Tor connection refused. Is Tor Browser running?")
            st.session_state.tor_status = False
            return False
        except requests.exceptions.Timeout:
            st.error("Tor connection timed out. Tor might be slow or not working.")
            st.session_state.tor_status = False
            return False
        except Exception as e:
            st.error(f"Tor connection test failed: {e}")
            st.session_state.tor_status = False
            return False

    @staticmethod
    def generate_qr_code(data):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        return img

# --- ADB Utilities ---
class ADBUtils:
    @staticmethod
    def get_connected_devices():
        try:
            result = subprocess.run(
                [Config.ADB_PATH, "devices"],
                capture_output=True,
                text=True,
                timeout=10
            )
            devices = [
                line.split("\t")[0]
                for line in result.stdout.splitlines()
                if "\tdevice" in line
            ]
            return True, devices
        except FileNotFoundError:
            return False, ["ADB executable not found at specified path"]
        except subprocess.TimeoutExpired:
            return False, ["ADB command timed out"]
        except Exception as e:
            return False, [f"ADB error: {str(e)}"]

    @staticmethod
    def pull_logs(device_id=None, timeout=120):
        try:
            os.makedirs("adb_logs", exist_ok=True)
            clear_cmd = [Config.ADB_PATH]
            if device_id:
                clear_cmd.extend(["-s", device_id])
            clear_cmd.extend(["logcat", "-c"])
            subprocess.run(clear_cmd, timeout=10)
            logcat_path = os.path.join("adb_logs", "logcat.txt")
            log_cmd = [Config.ADB_PATH]
            if device_id:
                log_cmd.extend(["-s", device_id])
            log_cmd.extend(["logcat", "-d", "-t", "500"])
            with open(logcat_path, "w", encoding='utf-8') as f:
                subprocess.run(log_cmd, stdout=f, timeout=timeout)
            accessible_paths = [
                "/sdcard/",
                "/storage/emulated/0/Download/",
                "/data/local/tmp/"
            ]
            success_msgs = [f"Main logs saved to {logcat_path}"]
            for path in accessible_paths:
                try:
                    local_path = os.path.join("adb_logs", path.strip("/").replace("/", "_"))
                    os.makedirs(local_path, exist_ok=True)
                    pull_cmd = [Config.ADB_PATH]
                    if device_id:
                        pull_cmd.extend(["-s", device_id])
                    pull_cmd.extend(["pull", path, local_path])
                    result = subprocess.run(pull_cmd, timeout=30)
                    if result.returncode == 0:
                        success_msgs.append(f"Pulled {path} to {local_path}")
                except Exception:
                    continue
            return True, "\n".join(success_msgs)
        except subprocess.TimeoutExpired:
            return False, "Log collection timed out (try with USB connection)"
        except Exception as e:
            return False, f"Critical error: {str(e)}"

    @staticmethod
    def get_adb_instructions():
        return """
        ### ADB Setup Instructions
        
        1. **Install ADB**:
           - Windows: Download [Android SDK Platform Tools](https://developer.android.com/studio/releases/platform-tools)
           - macOS: `brew install android-platform-tools`
           - Linux: `sudo apt install android-tools-adb`

        2. **Enable USB Debugging** on your Android device:
           - Go to Settings > About phone
           - Tap "Build number" 7 times to enable Developer options
           - Go back to Settings > Developer options
           - Enable "USB debugging"

        3. **Connect your device**:
           - Connect via USB cable
           - On your device, approve the debugging prompt
           - Verify connection: `adb devices` should show your device

        4. **For wireless debugging** (optional):
           - Connect via USB first
           - Run: `adb tcpip 5555`
           - Disconnect USB and run: `adb connect <device-ip>:5555`
        """

# --- PDF Report Generator ---
class PDFReport(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        self.add_page()
        self.set_font("Arial", size=12)
        
    def header(self):
        self.cell(0, 10, "Android Threat Intelligence Report", ln=True, align="C")
        self.ln(5)
        
    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", 0, 0, 'C')
        
    def generate_report(self, username, results):
        self.set_font("Arial", "B", 16)
        self.cell(0, 10, "THREAT ANALYSIS REPORT", ln=True, align="C")
        self.ln(10)
        self.set_font("Arial", size=10)
        self.cell(0, 7, f"Generated by: {username}", ln=True)
        self.cell(0, 7, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        self.ln(15)
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, "Detection Results:", ln=True)
        self.ln(5)
        self.set_font("Arial", size=10)
        
        if not results:
            self.multi_cell(0, 7, "No analysis results to include in the report.", border=0)
            self.ln(2)
        else:
            for category, content in results:
                try:
                    self.multi_cell(0, 7, f"{category}: {content}", border=1)
                    self.ln(2)
                except Exception as e:
                    st.error(f"Error adding content to PDF for category '{category}': {e}")
                    self.multi_cell(0, 7, f"Error: Could not render '{category}': {content}", border=1)
                    self.ln(2)

        self.add_page()
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, "Quick Summary QR Code", ln=True, align="C")
        self.ln(5)
        
        try:
            summary = f"Threat Report\nUser: {username}\nFindings: {len(results)}"
            img = qrcode.make(summary)
            img_path = "temp_qr.png"
            img.save(img_path)
            self.image(img_path, x=50, w=100)
            os.remove(img_path)
        except Exception as e:
            st.error(f"Error generating or embedding QR code in PDF: {e}")
            self.multi_cell(0, 7, f"Error: Could not generate QR Code. {e}", border=0)
            self.ln(2)

# --- Threat Detection Functions ---
class ThreatDetector:
    @staticmethod
    def detect_hidden_apps(text):
        return re.findall(r'App Hidden from launcher: ([\w\.]+)', text)

    @staticmethod
    def detect_permissions(text):
        match = re.search(r'Dangerous Permissions: (.+)', text)
        return match.group(1).split(', ') if match else []

    @staticmethod
    def detect_spoofed_sms(text):
        return re.findall(r'SMS sent: .*http[s]?://[^\s]+', text)

    @staticmethod
    def detect_adb_usage(text):
        return "adb" in text.lower()

    @staticmethod
    def extract_locations(text):
        locations = []
        matches = re.finditer(
            r'Location captured: Latitude: ([\d\.-]+), Longitude: ([\d\.-]+)(?: at (.+))?', 
            text
        )
        for match in matches:
            try:
                locations.append({
                    "latitude": float(match.group(1)),
                    "longitude": float(match.group(2)),
                    "timestamp": match.group(3) or "Unknown time"
                })
            except ValueError:
                continue
        return locations

    @staticmethod
    def detect_dns_queries(text):
        return re.findall(r'DNS Query: ([\w\.-]+\.[a-z]{2,})', text)

    @staticmethod
    def detect_ip_addresses(text):
        return re.findall(r'IP Detected: (\d+\.\d+\.\d+\.\d+)', text)

    @staticmethod
    def detect_ports(text):
        match = re.search(r'Ports? ([\d,\s]+) open', text)
        return match.group(1) if match else ""

    @staticmethod
    def extract_email_headers(text):
        match = re.search(r'Email Received: Header shows ([^\n]+)', text)
        return match.group(1) if match else ""

    @staticmethod
    def detect_bandwidth_spike(text):
        match = re.search(r'Bandwidth Spike: ([^\n]+)', text)
        return match.group(1) if match else ""

    @staticmethod
    def detect_malicious_urls(text):
        return re.findall(Config.THREAT_PATTERNS["Malicious URL"], text)

    @staticmethod
    def detect_ssh_keys(text):
        return re.findall(Config.THREAT_PATTERNS["SSH Key"], text)

    @staticmethod
    def smart_extract_threats(text):
        matches = []
        for label, pattern in Config.THREAT_PATTERNS.items():
            found = re.findall(pattern, text)
            for f in found[:5]: # Limit to first 5 matches per pattern for brevity
                matches.append((label, f))
        return matches

# --- OSINT Functions ---
class OSINTUtils:
    @staticmethod
    @st.cache_data(ttl=3600)
    def perform_whois(domain):
        try:
            info = whois.whois(domain)
            registrar = info.registrar[0] if isinstance(info.registrar, list) else info.registrar
            creation_date = info.creation_date[0] if isinstance(info.creation_date, list) else info.creation_date
            expiration_date = info.expiration_date[0] if isinstance(info.expiration_date, list) else info.expiration_date
            registrar = str(registrar) if registrar else "N/A"
            creation_date = str(creation_date) if creation_date else "N/A"
            expiration_date = str(expiration_date) if expiration_date else "N/A"
            return f"Registrar: {registrar}, Created: {creation_date}, Expires: {expiration_date}"
        except Exception as e:
            return f"WHOIS lookup failed for {domain}: {e}"

    @staticmethod
    @st.cache_data(ttl=3600)
    def geo_lookup(ip):
        try:
            handler = ipinfo.getHandler(Config.IPINFO_TOKEN)
            details = handler.getDetails(ip)
            result = {
                'ip': ip,
                'city': details.city or 'Unknown',
                'region': details.region or 'Unknown',
                'country': details.country_name or 'Unknown',
                'org': details.org or 'Unknown',
                'location': details.loc if details.loc and ',' in details.loc else '0,0',
                'postal': details.postal or 'Unknown'
            }
            return result
        except Exception as e:
            return {"error": f"IP lookup failed for {ip}: {e}", "location": "0,0"}

    @staticmethod
    def dns_lookup(domain):
        try:
            result = {}
            record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
            for record in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record)
                    result[record] = [str(r) for r in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue
                except Exception as e:
                    result[record] = f"Error: {str(e)}"
            return result if result else {"error": "No DNS records found"}
        except Exception as e:
            return {"error": f"DNS lookup failed: {str(e)}"}

# --- Dark Web Scanner ---
class DarkWebScanner:
    @staticmethod
    def search_ahmia(keyword):
        try:
            ahmia_url = f"https://ahmia.fi/search/?q={keyword}"
            session = requests.Session()
            session.proxies = Config.TOR_PROXY
            response = session.get(ahmia_url, timeout=25)
            response.raise_for_status()
            onion_links = re.findall(r"http[s]?://[a-z0-9]{16,56}\.onion", response.text)
            return list(set(onion_links))[:5]
        except requests.exceptions.Timeout:
            return [f"Ahmia search timed out for '{keyword}'. Ensure Tor is running."]
        except Exception as e:
            return [f"Ahmia search failed for '{keyword}': {e}"]

    @staticmethod
    def darkweb_real_request(onion_url):
        session = requests.Session()
        session.proxies = Config.TOR_PROXY
        try:
            response = session.get(onion_url, timeout=30)
            response.raise_for_status()
            return response.text[:5000]
        except requests.exceptions.Timeout:
            return f"Error: Request to {onion_url} timed out."
        except Exception as e:
            return f"Error accessing {onion_url}: {e}"

    @staticmethod
    def scan(keyword):
        cache_key = hashlib.md5(keyword.encode()).hexdigest()
        if cache_key in st.session_state.darkweb_cache:
            return st.session_state.darkweb_cache[cache_key]
        st.info(f"🔍 Scanning dark web for: '{keyword}'...")
        scan_results = []
        onion_sites = DarkWebScanner.search_ahmia(keyword)
        if not onion_sites or any("search timed out" in s for s in onion_sites):
            scan_results.append(f"Could not find .onion sites for '{keyword}' or encountered an error.")
            st.session_state.darkweb_cache[cache_key] = scan_results
            return scan_results
        progress_bar = st.progress(0)
        total_sites = len(onion_sites)
        for i, site in enumerate(onion_sites):
            progress_bar.progress((i + 1) / total_sites)
            st.markdown(f"Attempting to connect to: [`{site}`]({site})")
            content = DarkWebScanner.darkweb_real_request(site)
            if content.startswith("Error:"):
                scan_results.append(content)
                continue
            matches = ThreatDetector.smart_extract_threats(content)
            if matches:
                scan_results.append(f"✅ {len(matches)} threat(s) found at: {site}")
                for label, val in matches:
                    scan_results.append(f"🔸 {label}: {val}")
            else:
                scan_results.append(f"❌ No specific threats found at: {site}")
        progress_bar.empty()
        st.session_state.darkweb_cache[cache_key] = scan_results
        return scan_results

# --- Network Analysis ---
class NetworkAnalyzer:
    @staticmethod
    def analyze_network_traffic(text):
        results = {}
        ips = ThreatDetector.detect_ip_addresses(text)
        if ips:
            results["IP Analysis"] = []
            for ip in set(ips[:5]):
                geo_info = OSINTUtils.geo_lookup(ip)
                if isinstance(geo_info, dict) and 'error' not in geo_info and geo_info['location'] != '0,0':
                    results["IP Analysis"].append({
                        "IP": ip,
                        "Location": f"{geo_info['city']}, {geo_info['region']}, {geo_info['country']}",
                        "Organization": geo_info['org'],
                        "Coordinates": geo_info['location']
                    })
                else:
                    results["IP Analysis"].append({
                        "IP": ip,
                        "Location": "Unknown",
                        "Organization": "Unknown",
                        "Coordinates": "0,0"
                    })
        domains = ThreatDetector.detect_dns_queries(text)
        if domains:
            results["Domain Analysis"] = []
            for domain in set(domains[:5]):
                dns_info = OSINTUtils.dns_lookup(domain)
                if isinstance(dns_info, dict) and 'error' not in dns_info:
                    results["Domain Analysis"].append({
                        "Domain": domain,
                        "DNS Records": dns_info
                    })
        return results if results else None

# --- Malware Scanner ---
class MalwareScanner:
    # Initial set of dummy known malicious hashes for demonstration.
    # In a real-world scenario, this would be loaded from a database or external feed.
    INITIAL_MALICIOUS_HASHES = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty file (often used by benign tools, but could be suspicious in certain contexts)",
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2": "Example Ransomware Variant (dummy hash)",
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef": "Example Spyware (dummy hash)"
    }

    # A set of new dummy hashes that can be "updated" into the system
    NEW_MALICIOUS_HASHES_UPDATE = {
        "f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1": "Example Trojan Dropper (simulated new threat)",
        "9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba": "Example Adware (simulated new threat)",
        "abc123def456abc123def456abc123def456abc123def456abc123def456abc12": "Example Rootkit Component (simulated new threat)",
        "0000000000000000000000000000000000000000000000000000000000000001": "WannaCry Ransomware (simulated signature)",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": "Zeus Botnet (simulated signature)"
    }

    @staticmethod
    def calculate_sha256(file_content):
        """Calculates the SHA256 hash of the given file content."""
        return hashlib.sha256(file_content).hexdigest()

    @staticmethod
    def scan_file_content(text_content):
        """Scans text content for known threat patterns."""
        return ThreatDetector.smart_extract_threats(text_content)

    @staticmethod
    def update_known_hashes():
        """Simulates updating the known malicious hashes from an external source."""
        # In a real application, this would involve API calls to threat intelligence platforms.
        # Here, we're just adding a predefined set of "new" hashes.
        new_hashes_added = 0
        for h, desc in MalwareScanner.NEW_MALICIOUS_HASHES_UPDATE.items():
            if h not in st.session_state.known_malicious_hashes:
                st.session_state.known_malicious_hashes[h] = desc
                new_hashes_added += 1
        return new_hashes_added

# --- Traceroute Analyzer ---
class TracerouteAnalyzer:
    @staticmethod
    def run_traceroute(target):
        """
        Runs traceroute/tracert command and parses the output to extract hop IPs.
        Returns raw output and a list of IP addresses for each hop.
        """
        raw_output = ""
        hop_ips = []
        
        if sys.platform.startswith('win'):
            command = ["tracert", "-d", target] # -d to avoid resolving hostnames
            ip_pattern = r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?" # Matches IPs in brackets or not
        else: # Linux, macOS
            command = ["traceroute", "-n", target] # -n to avoid resolving hostnames
            ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b" # Matches standard IPs

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300, # Increased timeout for potentially long traceroutes
                check=True
            )
            raw_output = process.stdout
            
            for line in raw_output.splitlines():
                # Extract all IPs from the line, as some hops might show multiple
                found_ips = re.findall(ip_pattern, line)
                for ip in found_ips:
                    # Basic validation for valid IPv4 range (not perfect, but good enough for common use)
                    parts = list(map(int, ip.split('.')))
                    if all(0 <= p <= 255 for p in parts):
                        hop_ips.append(ip)
            
        except subprocess.CalledProcessError as e:
            raw_output = f"Error running traceroute: {e.stderr}"
            st.error(f"Traceroute command failed: {e.stderr}")
        except subprocess.TimeoutExpired:
            raw_output = "Traceroute command timed out."
            st.error("Traceroute command timed out.")
        except FileNotFoundError:
            raw_output = f"Traceroute command not found. Please ensure 'tracert' (Windows) or 'traceroute' (Linux/macOS) is installed and in your PATH."
            st.error(raw_output)
        except Exception as e:
            raw_output = f"An unexpected error occurred during traceroute: {e}"
            st.error(f"An unexpected error occurred during traceroute: {e}")
            
        return raw_output, list(dict.fromkeys(hop_ips)) # Use dict.fromkeys to preserve order and remove duplicates

    @staticmethod
    def get_hop_locations(hop_ips):
        """
        Performs geolocation lookup for a list of IP addresses.
        Returns a list of dictionaries with 'latitude', 'longitude', and 'ip'.
        """
        locations = []
        if not Config.IPINFO_TOKEN or Config.IPINFO_TOKEN == "YOUR_IPINFO_TOKEN":
            st.warning("IPINFO_TOKEN is not configured. IP geolocation will not work.")
            return []

        for ip in hop_ips:
            geo_info = OSINTUtils.geo_lookup(ip)
            if isinstance(geo_info, dict) and 'error' not in geo_info and geo_info['location'] != '0,0':
                lat, lon = map(float, geo_info['location'].split(','))
                locations.append({
                    "latitude": lat,
                    "longitude": lon,
                    "ip": ip,
                    "city": geo_info.get('city', 'Unknown'),
                    "country": geo_info.get('country', 'Unknown')
                })
        return locations

# --- Port Scanner ---
class PortScanner:
    @staticmethod
    def scan_port(target_host, target_port, timeout=1):
        """
        Attempts to connect to a specific port on a target host.
        Returns True if the port is open, False otherwise.
        """
        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set a timeout for the connection attempt
            s.settimeout(timeout)
            # Attempt to connect to the target host and port
            result = s.connect_ex((target_host, target_port))
            s.close()
            # If result is 0, the connection was successful (port is open)
            if result == 0:
                return True
            else:
                return False
        except socket.gaierror:
            # Hostname resolution error
            return "Hostname could not be resolved."
        except socket.error as e:
            # Other socket-related errors
            return f"Socket error: {e}"
        except Exception as e:
            # Catch any other unexpected errors
            return f"An unexpected error occurred: {e}"

    @staticmethod
    def scan_range(target_host, start_port, end_port):
        """
        Scans a range of ports on a target host.
        Returns a list of open ports.
        """
        open_ports = []
        st.write(f"Scanning ports {start_port}-{end_port} on {target_host}...")
        
        # Get the IP address from the hostname, if a hostname is provided
        try:
            target_ip = socket.gethostbyname(target_host)
        except socket.gaierror:
            st.error(f"Error: Hostname '{target_host}' could not be resolved.")
            return []

        # Create a progress bar for the scan
        progress_text = "Scanning in progress. Please wait."
        my_bar = st.progress(0, text=progress_text)
        
        total_ports = end_port - start_port + 1
        
        for i, port in enumerate(range(start_port, end_port + 1)):
            status = PortScanner.scan_port(target_ip, port)
            if status is True:
                open_ports.append(port)
            elif isinstance(status, str): # Handle error messages from scan_port
                st.warning(f"Port {port}: {status}") # Display error for specific port
            
            # Update progress bar
            progress_percentage = (i + 1) / total_ports
            my_bar.progress(progress_percentage, text=f"{progress_text} ({int(progress_percentage*100)}%)")
            
        my_bar.empty() # Remove the progress bar after completion
        return open_ports


# --- UI Components ---
# --- IMPORTANT: MainUI is defined BEFORE AuthUI to ensure proper loading ---
class MainUI:
    @staticmethod
    def render_enhanced_map(locations):
        if not locations:
            st.warning("No location data available")
            return
        
        st.subheader("Location Visualization")
        tab1, tab2, tab3 = st.tabs(["Interactive Map", "Timeline", "Heatmap"])
        
        with tab1:
            first_loc = locations[0]
            m = folium.Map(
                location=[first_loc["latitude"], first_loc["longitude"]],
                zoom_start=10,
                tiles="OpenStreetMap"
            )
            for loc in locations:
                folium.Marker(
                    [loc["latitude"], loc["longitude"]],
                    popup=f"Time: {loc.get('timestamp', 'N/A')}<br>IP: {loc.get('ip', 'N/A')}<br>City: {loc.get('city', 'N/A')}",
                    tooltip=f"Lat: {loc['latitude']}, Lon: {loc['longitude']}"
                ).add_to(m)
            folium.PolyLine(
                [[loc["latitude"], loc["longitude"]] for loc in locations],
                color="blue",
                weight=2.5,
                opacity=1
            ).add_to(m)
            folium_static(m, width=800, height=500)
        
        with tab2:
            df = pd.DataFrame(locations)
            # Ensure 'timestamp' column exists before converting
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                if df['timestamp'].isnull().all():
                    st.warning("No valid timestamps found for timeline.")
                else:
                    st.line_chart(
                        df.set_index('timestamp')[['latitude', 'longitude']],
                        use_container_width=True
                    )
            else:
                st.warning("No timestamp data available for timeline.")
        
        with tab3:
            m = folium.Map(
                location=[first_loc["latitude"], first_loc["longitude"]],
                zoom_start=10,
                tiles="OpenStreetMap"
            )
            from folium.plugins import HeatMap
            HeatMap(
                [[loc["latitude"], loc["longitude"]] for loc in locations],
                radius=15
            ).add_to(m)
            folium_static(m, width=800, height=500)

    @staticmethod
    def render_network_analysis(network_data):
        if not network_data:
            st.warning("No network data available for analysis")
            return
        
        st.subheader("Network Traffic Analysis")
        
        if "IP Analysis" in network_data and network_data["IP Analysis"]:
            st.markdown("### IP Address Analysis")
            ip_df = pd.DataFrame(network_data["IP Analysis"])
            
            # Filter valid coordinates
            valid_coords = [
                row for row in network_data["IP Analysis"]
                if isinstance(row.get('Coordinates'), str) and 
                   ',' in row['Coordinates'] and 
                   len(row['Coordinates'].split(',')) == 2 and
                   all(
                       x.replace('.', '', 1).replace('-', '', 1).isdigit()
                       for x in row['Coordinates'].split(',')
                   ) and
                   row['Coordinates'] != '0,0'
            ]
            
            if valid_coords:
                try:
                    valid_df = pd.DataFrame(valid_coords)
                    first_coords = valid_coords[0]['Coordinates'].split(',')
                    latitude = float(first_coords[0])
                    longitude = float(first_coords[1])
                    
                    valid_df['latitude'] = valid_df['Coordinates'].apply(lambda x: float(x.split(',')[0]))
                    valid_df['longitude'] = valid_df['Coordinates'].apply(lambda x: float(x.split(',')[1]))
                    
                    st.pydeck_chart(pdk.Deck(
                        map_style='mapbox://styles/mapbox/light-v9',
                        initial_view_state=pdk.ViewState(
                            latitude=latitude,
                            longitude=longitude,
                            zoom=1,
                            pitch=0,
                        ),
                        layers=[
                            pdk.Layer(
                                'ScatterplotLayer',
                                data=valid_df,
                                get_position='[longitude, latitude]',
                                get_color='[200, 30, 0, 160]',
                                get_radius=200000,
                                pickable=True
                            )
                        ],
                        tooltip={
                            "html": "<b>IP:</b> {IP}<br><b>Location:</b> {Location}<br><b>Org:</b> {Organization}",
                            "style": {"color": "white"}
                        }
                    ))
                except Exception as e:
                    st.error(f"Failed to render IP map: {str(e)}")
            else:
                st.warning("No valid coordinates available for IP mapping")
            
            st.dataframe(
                ip_df.drop(columns=['Coordinates'], errors='ignore'),
                use_container_width=True
            )
        else:
            st.warning("No valid IP address data available for analysis")
        
        if "Domain Analysis" in network_data:
            st.markdown("### 🔗 Domain Analysis")
            for domain_info in network_data["Domain Analysis"]:
                with st.expander(f"Domain: {domain_info['Domain']}"):
                    for record_type, records in domain_info["DNS Records"].items():
                        st.markdown(f"**{record_type} Records:**")
                        if isinstance(records, list):
                            for r in records:
                                st.code(r, language='text')
                        else:
                            st.code(records, language='text')

    @staticmethod
    def render_malware_scanner():
        st.subheader("Malware Signature Scanner")
        st.write("Upload a file to calculate its SHA256 hash and scan its content for known malicious signatures.")
        

        # Button to simulate updating signatures
        if st.button("Update Malware Signatures (Simulated)"):
            new_hashes_count = MalwareScanner.update_known_hashes()
            st.success(f"Simulated update complete! Added {new_hashes_count} new signatures.")
            st.info(f"Total signatures now: {len(st.session_state.known_malicious_hashes)}")


        uploaded_file = st.file_uploader("Upload a file for scanning", type=None) # Allow any file type

        if uploaded_file:
            st.markdown("---")
            st.write(f"**File Name:** `{uploaded_file.name}`")
            st.write(f"**File Type:** `{uploaded_file.type}`")
            st.write(f"**File Size:** `{uploaded_file.size / 1024:.2f} KB`")

            file_content = uploaded_file.read()
            
            # Calculate SHA256 hash
            file_hash = MalwareScanner.calculate_sha256(file_content)
            st.write(f"**SHA256 Hash:** `{file_hash}`")

            # Check hash against known malicious hashes (from session state)
            if file_hash in st.session_state.known_malicious_hashes:
                st.error(f"**Known Malicious Hash Detected!**")
                st.error(f"Reason: {st.session_state.known_malicious_hashes[file_hash]}")
                st.session_state.report_results.append(["Malware Scan (Hash)", f"Threat: Known malicious hash ({file_hash}) - {st.session_state.known_malicious_hashes[file_hash]}"])
            else:
                st.success("File hash is not in the known malicious database.")
                st.session_state.report_results.append(["Malware Scan (Hash)", f"No known malicious hash detected for {file_hash}."])

            st.markdown("---")
            st.write("### Content Scan for Threat Patterns")
            try:
                # Attempt to decode content as text for pattern scanning
                text_content = file_content.decode("utf-8", errors='ignore')
                content_threats = MalwareScanner.scan_file_content(text_content)

                if content_threats:
                    st.warning(f"⚠️ **{len(content_threats)} potential threat patterns found in file content!**")
                    for label, value in content_threats:
                        st.write(f"🔸 **{label}:** `{value}`")
                        st.session_state.report_results.append(["Malware Scan (Content)", f"Threat: {label}: {value}"])
                else:
                    st.info("No common threat patterns detected in file content.")
                    st.session_state.report_results.append(["Malware Scan (Content)", "No common threat patterns detected."])

            except Exception as e:
                st.warning(f"Could not decode file content for text-based scanning (e.g., it might be a binary file). Error: {e}")
                st.session_state.report_results.append(["Malware Scan (Content)", f"Could not scan content: {e}"])
            
            st.markdown("---")
            st.info("Results added to the Analysis Report tab.")

# --- Traceroute Analyzer ---
class TracerouteAnalyzer:
    @staticmethod
    def run_traceroute(target):
        """
        Runs traceroute/tracert command and parses the output to extract hop IPs.
        Returns raw output and a list of IP addresses for each hop.
        """
        raw_output = ""
        hop_ips = []
        
        if sys.platform.startswith('win'):
            command = ["tracert", "-d", target] # -d to avoid resolving hostnames
            ip_pattern = r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?" # Matches IPs in brackets or not
        else: # Linux, macOS
            command = ["traceroute", "-n", target] # -n to avoid resolving hostnames
            ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b" # Matches standard IPs

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300, # Increased timeout for potentially long traceroutes
                check=True
            )
            raw_output = process.stdout
            
            for line in raw_output.splitlines():
                # Extract all IPs from the line, as some hops might show multiple
                found_ips = re.findall(ip_pattern, line)
                for ip in found_ips:
                    # Basic validation for valid IPv4 range (not perfect, but good enough for common use)
                    parts = list(map(int, ip.split('.')))
                    if all(0 <= p <= 255 for p in parts):
                        hop_ips.append(ip)
            
        except subprocess.CalledProcessError as e:
            raw_output = f"Error running traceroute: {e.stderr}"
            st.error(f"Traceroute command failed: {e.stderr}")
        except subprocess.TimeoutExpired:
            raw_output = "Traceroute command timed out."
            st.error("Traceroute command timed out.")
        except FileNotFoundError:
            raw_output = f"Traceroute command not found. Please ensure 'tracert' (Windows) or 'traceroute' (Linux/macOS) is installed and in your PATH."
            st.error(raw_output)
        except Exception as e:
            raw_output = f"An unexpected error occurred during traceroute: {e}"
            st.error(f"An unexpected error occurred during traceroute: {e}")
            
        return raw_output, list(dict.fromkeys(hop_ips)) # Use dict.fromkeys to preserve order and remove duplicates

    @staticmethod
    def get_hop_locations(hop_ips):
        """
        Performs geolocation lookup for a list of IP addresses.
        Returns a list of dictionaries with 'latitude', 'longitude', and 'ip'.
        """
        locations = []
        if not Config.IPINFO_TOKEN or Config.IPINFO_TOKEN == "YOUR_IPINFO_TOKEN":
            st.warning("IPINFO_TOKEN is not configured. IP geolocation will not work.")
            return []

        for ip in hop_ips:
            geo_info = OSINTUtils.geo_lookup(ip)
            if isinstance(geo_info, dict) and 'error' not in geo_info and geo_info['location'] != '0,0':
                lat, lon = map(float, geo_info['location'].split(','))
                locations.append({
                    "latitude": lat,
                    "longitude": lon,
                    "ip": ip,
                    "city": geo_info.get('city', 'Unknown'),
                    "country": geo_info.get('country', 'Unknown')
                })
        return locations

# --- Port Scanner ---
class PortScanner:
    @staticmethod
    def scan_port(target_host, target_port, timeout=1):
        """
        Attempts to connect to a specific port on a target host.
        Returns True if the port is open, False otherwise.
        """
        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set a timeout for the connection attempt
            s.settimeout(timeout)
            # Attempt to connect to the target host and port
            result = s.connect_ex((target_host, target_port))
            s.close()
            # If result is 0, the connection was successful (port is open)
            if result == 0:
                return True
            else:
                return False
        except socket.gaierror:
            # Hostname resolution error
            return "Hostname could not be resolved."
        except socket.error as e:
            # Other socket-related errors
            return f"Socket error: {e}"
        except Exception as e:
            # Catch any other unexpected errors
            return f"An unexpected error occurred: {e}"

    @staticmethod
    def scan_range(target_host, start_port, end_port):
        """
        Scans a range of ports on a target host.
        Returns a list of open ports.
        """
        open_ports = []
        st.write(f"Scanning ports {start_port}-{end_port} on {target_host}...")
        
        # Get the IP address from the hostname, if a hostname is provided
        try:
            target_ip = socket.gethostbyname(target_host)
        except socket.gaierror:
            st.error(f"Error: Hostname '{target_host}' could not be resolved.")
            return []

        # Create a progress bar for the scan
        progress_text = "Scanning in progress. Please wait."
        my_bar = st.progress(0, text=progress_text)
        
        total_ports = end_port - start_port + 1
        
        for i, port in enumerate(range(start_port, end_port + 1)):
            status = PortScanner.scan_port(target_ip, port)
            if status is True:
                open_ports.append(port)
            elif isinstance(status, str): # Handle error messages from scan_port
                st.warning(f"Port {port}: {status}") # Display error for specific port
            
            # Update progress bar
            progress_percentage = (i + 1) / total_ports
            my_bar.progress(progress_percentage, text=f"{progress_text} ({int(progress_percentage*100)}%)")
            
        my_bar.empty() # Remove the progress bar after completion
        return open_ports


# --- UI Components ---
# --- IMPORTANT: MainUI is defined BEFORE AuthUI to ensure proper loading ---
class MainUI:
    @staticmethod
    def render_enhanced_map(locations):
        if not locations:
            st.warning("No location data available")
            return
        
        st.subheader("Enhanced Location Visualization")
        tab1, tab2, tab3 = st.tabs(["Interactive Map", "Timeline", "Heatmap"])
        
        with tab1:
            first_loc = locations[0]
            m = folium.Map(
                location=[first_loc["latitude"], first_loc["longitude"]],
                zoom_start=10,
                tiles="OpenStreetMap"
            )
            for loc in locations:
                folium.Marker(
                    [loc["latitude"], loc["longitude"]],
                    popup=f"Time: {loc.get('timestamp', 'N/A')}<br>IP: {loc.get('ip', 'N/A')}<br>City: {loc.get('city', 'N/A')}",
                    tooltip=f"Lat: {loc['latitude']}, Lon: {loc['longitude']}"
                ).add_to(m)
            folium.PolyLine(
                [[loc["latitude"], loc["longitude"]] for loc in locations],
                color="blue",
                weight=2.5,
                opacity=1
            ).add_to(m)
            folium_static(m, width=800, height=500)
        
        with tab2:
            df = pd.DataFrame(locations)
            # Ensure 'timestamp' column exists before converting
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                if df['timestamp'].isnull().all():
                    st.warning("No valid timestamps found for timeline.")
                else:
                    st.line_chart(
                        df.set_index('timestamp')[['latitude', 'longitude']],
                        use_container_width=True
                    )
            else:
                st.warning("No timestamp data available for timeline.")
        
        with tab3:
            m = folium.Map(
                location=[first_loc["latitude"], first_loc["longitude"]],
                zoom_start=10,
                tiles="OpenStreetMap"
            )
            from folium.plugins import HeatMap
            HeatMap(
                [[loc["latitude"], loc["longitude"]] for loc in locations],
                radius=15
            ).add_to(m)
            folium_static(m, width=800, height=500)

    @staticmethod
    def render_network_analysis(network_data):
        if not network_data:
            st.warning("No network data available for analysis")
            return
        
        st.subheader("🕸️ Network Traffic Analysis")
        
        if "IP Analysis" in network_data and network_data["IP Analysis"]:
            st.markdown("### IP Address Analysis")
            ip_df = pd.DataFrame(network_data["IP Analysis"])
            
            # Filter valid coordinates
            valid_coords = [
                row for row in network_data["IP Analysis"]
                if isinstance(row.get('Coordinates'), str) and 
                   ',' in row['Coordinates'] and 
                   len(row['Coordinates'].split(',')) == 2 and
                   all(
                       x.replace('.', '', 1).replace('-', '', 1).isdigit()
                       for x in row['Coordinates'].split(',')
                   ) and
                   row['Coordinates'] != '0,0'
            ]
            
            if valid_coords:
                try:
                    valid_df = pd.DataFrame(valid_coords)
                    first_coords = valid_coords[0]['Coordinates'].split(',')
                    latitude = float(first_coords[0])
                    longitude = float(first_coords[1])
                    
                    valid_df['latitude'] = valid_df['Coordinates'].apply(lambda x: float(x.split(',')[0]))
                    valid_df['longitude'] = valid_df['Coordinates'].apply(lambda x: float(x.split(',')[1]))
                    
                    st.pydeck_chart(pdk.Deck(
                        map_style='mapbox://styles/mapbox/light-v9',
                        initial_view_state=pdk.ViewState(
                            latitude=latitude,
                            longitude=longitude,
                            zoom=1,
                            pitch=0,
                        ),
                        layers=[
                            pdk.Layer(
                                'ScatterplotLayer',
                                data=valid_df,
                                get_position='[longitude, latitude]',
                                get_color='[200, 30, 0, 160]',
                                get_radius=200000,
                                pickable=True
                            )
                        ],
                        tooltip={
                            "html": "<b>IP:</b> {IP}<br><b>Location:</b> {Location}<br><b>Org:</b> {Organization}",
                            "style": {"color": "white"}
                        }
                    ))
                except Exception as e:
                    st.error(f"Failed to render IP map: {str(e)}")
            else:
                st.warning("No valid coordinates available for IP mapping")
            
            st.dataframe(
                ip_df.drop(columns=['Coordinates'], errors='ignore'),
                use_container_width=True
            )
        else:
            st.warning("No valid IP address data available for analysis")
        
        if "Domain Analysis" in network_data:
            st.markdown("### 🔗 Domain Analysis")
            for domain_info in network_data["Domain Analysis"]:
                with st.expander(f"Domain: {domain_info['Domain']}"):
                    for record_type, records in domain_info["DNS Records"].items():
                        st.markdown(f"**{record_type} Records:**")
                        if isinstance(records, list):
                            for r in records:
                                st.code(r, language='text')
                        else:
                            st.code(records, language='text')

    @staticmethod
    def render_malware_scanner():
        st.subheader("Malware Signature Scanner")
        st.write("Upload a file to calculate its SHA256 hash and scan its content for known malicious signatures.")
        st.info("""
        **Note on Real-time Signatures:**
        In a professional setting, real-time malware signatures are typically obtained from constantly updated, external threat intelligence platforms (e.g., VirusTotal, commercial AV engines) via their APIs. This application uses a local, predefined set of signatures for demonstration.
        """)

        # Button to simulate updating signatures
        if st.button("Update Malware Signatures (Simulated)"):
            new_hashes_count = MalwareScanner.update_known_hashes()
            st.success(f"Simulated update complete! Added {new_hashes_count} new signatures.")
            st.info(f"Total signatures now: {len(st.session_state.known_malicious_hashes)}")


        uploaded_file = st.file_uploader("Upload a file for scanning", type=None) # Allow any file type

        if uploaded_file:
            st.markdown("---")
            st.write(f"**File Name:** `{uploaded_file.name}`")
            st.write(f"**File Type:** `{uploaded_file.type}`")
            st.write(f"**File Size:** `{uploaded_file.size / 1024:.2f} KB`")

            file_content = uploaded_file.read()
            
            # Calculate SHA256 hash
            file_hash = MalwareScanner.calculate_sha256(file_content)
            st.write(f"**SHA256 Hash:** `{file_hash}`")

            # Check hash against known malicious hashes (from session state)
            if file_hash in st.session_state.known_malicious_hashes:
                st.error(f"🚨 **Known Malicious Hash Detected!**")
                st.error(f"Reason: {st.session_state.known_malicious_hashes[file_hash]}")
                st.session_state.report_results.append(["Malware Scan (Hash)", f"Threat: Known malicious hash ({file_hash}) - {st.session_state.known_malicious_hashes[file_hash]}"])
            else:
                st.success("✅ File hash is not in the known malicious database.")
                st.session_state.report_results.append(["Malware Scan (Hash)", f"No known malicious hash detected for {file_hash}."])

            st.markdown("---")
            st.write("### Content Scan for Threat Patterns")
            try:
                # Attempt to decode content as text for pattern scanning
                text_content = file_content.decode("utf-8", errors='ignore')
                content_threats = MalwareScanner.scan_file_content(text_content)

                if content_threats:
                    st.warning(f"⚠️ **{len(content_threats)} potential threat patterns found in file content!**")
                    for label, value in content_threats:
                        st.write(f"🔸 **{label}:** `{value}`")
                        st.session_state.report_results.append(["Malware Scan (Content)", f"Threat: {label}: {value}"])
                else:
                    st.info("No common threat patterns detected in file content.")
                    st.session_state.report_results.append(["Malware Scan (Content)", "No common threat patterns detected."])

            except Exception as e:
                st.warning(f"Could not decode file content for text-based scanning (e.g., it might be a binary file). Error: {e}")
                st.session_state.report_results.append(["Malware Scan (Content)", f"Could not scan content: {e}"])
            
            st.markdown("---")
            st.info("Results added to the Analysis Report tab.")

# --- Traceroute Analyzer ---
class TracerouteAnalyzer:
    @staticmethod
    def run_traceroute(target):
        """
        Runs traceroute/tracert command and parses the output to extract hop IPs.
        Returns raw output and a list of IP addresses for each hop.
        """
        raw_output = ""
        hop_ips = []
        
        if sys.platform.startswith('win'):
            command = ["tracert", "-d", target] # -d to avoid resolving hostnames
            ip_pattern = r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?" # Matches IPs in brackets or not
        else: # Linux, macOS
            command = ["traceroute", "-n", target] # -n to avoid resolving hostnames
            ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b" # Matches standard IPs

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300, # Increased timeout for potentially long traceroutes
                check=True
            )
            raw_output = process.stdout
            
            for line in raw_output.splitlines():
                # Extract all IPs from the line, as some hops might show multiple
                found_ips = re.findall(ip_pattern, line)
                for ip in found_ips:
                    # Basic validation for valid IPv4 range (not perfect, but good enough for common use)
                    parts = list(map(int, ip.split('.')))
                    if all(0 <= p <= 255 for p in parts):
                        hop_ips.append(ip)
            
        except subprocess.CalledProcessError as e:
            raw_output = f"Error running traceroute: {e.stderr}"
            st.error(f"Traceroute command failed: {e.stderr}")
        except subprocess.TimeoutExpired:
            raw_output = "Traceroute command timed out."
            st.error("Traceroute command timed out.")
        except FileNotFoundError:
            raw_output = f"Traceroute command not found. Please ensure 'tracert' (Windows) or 'traceroute' (Linux/macOS) is installed and in your PATH."
            st.error(raw_output)
        except Exception as e:
            raw_output = f"An unexpected error occurred during traceroute: {e}"
            st.error(f"An unexpected error occurred during traceroute: {e}")
            
        return raw_output, list(dict.fromkeys(hop_ips)) # Use dict.fromkeys to preserve order and remove duplicates

    @staticmethod
    def get_hop_locations(hop_ips):
        """
        Performs geolocation lookup for a list of IP addresses.
        Returns a list of dictionaries with 'latitude', 'longitude', and 'ip'.
        """
        locations = []
        if not Config.IPINFO_TOKEN or Config.IPINFO_TOKEN == "YOUR_IPINFO_TOKEN":
            st.warning("IPINFO_TOKEN is not configured. IP geolocation will not work.")
            return []

        for ip in hop_ips:
            geo_info = OSINTUtils.geo_lookup(ip)
            if isinstance(geo_info, dict) and 'error' not in geo_info and geo_info['location'] != '0,0':
                lat, lon = map(float, geo_info['location'].split(','))
                locations.append({
                    "latitude": lat,
                    "longitude": lon,
                    "ip": ip,
                    "city": geo_info.get('city', 'Unknown'),
                    "country": geo_info.get('country', 'Unknown')
                })
        return locations

# --- Port Scanner ---
class PortScanner:
    @staticmethod
    def scan_port(target_host, target_port, timeout=1):
        """
        Attempts to connect to a specific port on a target host.
        Returns True if the port is open, False otherwise.
        """
        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set a timeout for the connection attempt
            s.settimeout(timeout)
            # Attempt to connect to the target host and port
            result = s.connect_ex((target_host, target_port))
            s.close()
            # If result is 0, the connection was successful (port is open)
            if result == 0:
                return True
            else:
                return False
        except socket.gaierror:
            # Hostname resolution error
            return "Hostname could not be resolved."
        except socket.error as e:
            # Other socket-related errors
            return f"Socket error: {e}"
        except Exception as e:
            # Catch any other unexpected errors
            return f"An unexpected error occurred: {e}"

    @staticmethod
    def scan_range(target_host, start_port, end_port):
        """
        Scans a range of ports on a target host.
        Returns a list of open ports.
        """
        open_ports = []
        st.write(f"Scanning ports {start_port}-{end_port} on {target_host}...")
        
        # Get the IP address from the hostname, if a hostname is provided
        try:
            target_ip = socket.gethostbyname(target_host)
        except socket.gaierror:
            st.error(f"Error: Hostname '{target_host}' could not be resolved.")
            return []

        # Create a progress bar for the scan
        progress_text = "Scanning in progress. Please wait."
        my_bar = st.progress(0, text=progress_text)
        
        total_ports = end_port - start_port + 1
        
        for i, port in enumerate(range(start_port, end_port + 1)):
            status = PortScanner.scan_port(target_ip, port)
            if status is True:
                open_ports.append(port)
            elif isinstance(status, str): # Handle error messages from scan_port
                st.warning(f"Port {port}: {status}") # Display error for specific port
            
            # Update progress bar
            progress_percentage = (i + 1) / total_ports
            my_bar.progress(progress_percentage, text=f"{progress_text} ({int(progress_percentage*100)}%)")
            
        my_bar.empty() # Remove the progress bar after completion
        return open_ports


# --- UI Components ---
# --- IMPORTANT: MainUI is defined BEFORE AuthUI to ensure proper loading ---
class MainUI:
    @staticmethod
    def render_enhanced_map(locations):
        if not locations:
            st.warning("No location data available")
            return
        
        st.subheader("🌍 Enhanced Location Visualization")
        tab1, tab2, tab3 = st.tabs(["Interactive Map", "Timeline", "Heatmap"])
        
        with tab1:
            first_loc = locations[0]
            m = folium.Map(
                location=[first_loc["latitude"], first_loc["longitude"]],
                zoom_start=10,
                tiles="OpenStreetMap"
            )
            for loc in locations:
                folium.Marker(
                    [loc["latitude"], loc["longitude"]],
                    popup=f"Time: {loc.get('timestamp', 'N/A')}<br>IP: {loc.get('ip', 'N/A')}<br>City: {loc.get('city', 'N/A')}",
                    tooltip=f"Lat: {loc['latitude']}, Lon: {loc['longitude']}"
                ).add_to(m)
            folium.PolyLine(
                [[loc["latitude"], loc["longitude"]] for loc in locations],
                color="blue",
                weight=2.5,
                opacity=1
            ).add_to(m)
            folium_static(m, width=800, height=500)
        
        with tab2:
            df = pd.DataFrame(locations)
            # Ensure 'timestamp' column exists before converting
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                if df['timestamp'].isnull().all():
                    st.warning("No valid timestamps found for timeline.")
                else:
                    st.line_chart(
                        df.set_index('timestamp')[['latitude', 'longitude']],
                        use_container_width=True
                    )
            else:
                st.warning("No timestamp data available for timeline.")
        
        with tab3:
            m = folium.Map(
                location=[first_loc["latitude"], first_loc["longitude"]],
                zoom_start=10,
                tiles="OpenStreetMap"
            )
            from folium.plugins import HeatMap
            HeatMap(
                [[loc["latitude"], loc["longitude"]] for loc in locations],
                radius=15
            ).add_to(m)
            folium_static(m, width=800, height=500)

    @staticmethod
    def render_network_analysis(network_data):
        if not network_data:
            st.warning("No network data available for analysis")
            return
        
        st.subheader("🕸️ Network Traffic Analysis")
        
        if "IP Analysis" in network_data and network_data["IP Analysis"]:
            st.markdown("### 🌐 IP Address Analysis")
            ip_df = pd.DataFrame(network_data["IP Analysis"])
            
            # Filter valid coordinates
            valid_coords = [
                row for row in network_data["IP Analysis"]
                if isinstance(row.get('Coordinates'), str) and 
                   ',' in row['Coordinates'] and 
                   len(row['Coordinates'].split(',')) == 2 and
                   all(
                       x.replace('.', '', 1).replace('-', '', 1).isdigit()
                       for x in row['Coordinates'].split(',')
                   ) and
                   row['Coordinates'] != '0,0'
            ]
            
            if valid_coords:
                try:
                    valid_df = pd.DataFrame(valid_coords)
                    first_coords = valid_coords[0]['Coordinates'].split(',')
                    latitude = float(first_coords[0])
                    longitude = float(first_coords[1])
                    
                    valid_df['latitude'] = valid_df['Coordinates'].apply(lambda x: float(x.split(',')[0]))
                    valid_df['longitude'] = valid_df['Coordinates'].apply(lambda x: float(x.split(',')[1]))
                    
                    st.pydeck_chart(pdk.Deck(
                        map_style='mapbox://styles/mapbox/light-v9',
                        initial_view_state=pdk.ViewState(
                            latitude=latitude,
                            longitude=longitude,
                            zoom=1,
                            pitch=0,
                        ),
                        layers=[
                            pdk.Layer(
                                'ScatterplotLayer',
                                data=valid_df,
                                get_position='[longitude, latitude]',
                                get_color='[200, 30, 0, 160]',
                                get_radius=200000,
                                pickable=True
                            )
                        ],
                        tooltip={
                            "html": "<b>IP:</b> {IP}<br><b>Location:</b> {Location}<br><b>Org:</b> {Organization}",
                            "style": {"color": "white"}
                        }
                    ))
                except Exception as e:
                    st.error(f"Failed to render IP map: {str(e)}")
            else:
                st.warning("No valid coordinates available for IP mapping")
            
            st.dataframe(
                ip_df.drop(columns=['Coordinates'], errors='ignore'),
                use_container_width=True
            )
        else:
            st.warning("No valid IP address data available for analysis")
        
        if "Domain Analysis" in network_data:
            st.markdown("### 🔗 Domain Analysis")
            for domain_info in network_data["Domain Analysis"]:
                with st.expander(f"Domain: {domain_info['Domain']}"):
                    for record_type, records in domain_info["DNS Records"].items():
                        st.markdown(f"**{record_type} Records:**")
                        if isinstance(records, list):
                            for r in records:
                                st.code(r, language='text')
                        else:
                            st.code(records, language='text')

    @staticmethod
    def render_malware_scanner():
        st.subheader("Malware Signature Scanner")
        st.write("Upload a file to calculate its SHA256 hash and scan its content for known malicious signatures.")
        

        # Button to simulate updating signatures
        if st.button("Update Malware Signatures (Simulated)"):
            new_hashes_count = MalwareScanner.update_known_hashes()
            st.success(f"Simulated update complete! Added {new_hashes_count} new signatures.")
            st.info(f"Total signatures now: {len(st.session_state.known_malicious_hashes)}")


        uploaded_file = st.file_uploader("Upload a file for scanning", type=None) # Allow any file type

        if uploaded_file:
            st.markdown("---")
            st.write(f"**File Name:** `{uploaded_file.name}`")
            st.write(f"**File Type:** `{uploaded_file.type}`")
            st.write(f"**File Size:** `{uploaded_file.size / 1024:.2f} KB`")

            file_content = uploaded_file.read()
            
            # Calculate SHA256 hash
            file_hash = MalwareScanner.calculate_sha256(file_content)
            st.write(f"**SHA256 Hash:** `{file_hash}`")

            # Check hash against known malicious hashes (from session state)
            if file_hash in st.session_state.known_malicious_hashes:
                st.error(f"🚨 **Known Malicious Hash Detected!**")
                st.error(f"Reason: {st.session_state.known_malicious_hashes[file_hash]}")
                st.session_state.report_results.append(["Malware Scan (Hash)", f"Threat: Known malicious hash ({file_hash}) - {st.session_state.known_malicious_hashes[file_hash]}"])
            else:
                st.success("✅ File hash is not in the known malicious database.")
                st.session_state.report_results.append(["Malware Scan (Hash)", f"No known malicious hash detected for {file_hash}."])

            st.markdown("---")
            st.write("### Content Scan for Threat Patterns")
            try:
                # Attempt to decode content as text for pattern scanning
                text_content = file_content.decode("utf-8", errors='ignore')
                content_threats = MalwareScanner.scan_file_content(text_content)

                if content_threats:
                    st.warning(f"⚠️ **{len(content_threats)} potential threat patterns found in file content!**")
                    for label, value in content_threats:
                        st.write(f"🔸 **{label}:** `{value}`")
                        st.session_state.report_results.append(["Malware Scan (Content)", f"Threat: {label}: {value}"])
                else:
                    st.info("No common threat patterns detected in file content.")
                    st.session_state.report_results.append(["Malware Scan (Content)", "No common threat patterns detected."])

            except Exception as e:
                st.warning(f"Could not decode file content for text-based scanning (e.g., it might be a binary file). Error: {e}")
                st.session_state.report_results.append(["Malware Scan (Content)", f"Could not scan content: {e}"])
            
            st.markdown("---")
            st.info("Results added to the Analysis Report tab.")

# --- Traceroute Analyzer ---
class TracerouteAnalyzer:
    @staticmethod
    def run_traceroute(target):
        """
        Runs traceroute/tracert command and parses the output to extract hop IPs.
        Returns raw output and a list of IP addresses for each hop.
        """
        raw_output = ""
        hop_ips = []
        
        if sys.platform.startswith('win'):
            command = ["tracert", "-d", target] # -d to avoid resolving hostnames
            ip_pattern = r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?" # Matches IPs in brackets or not
        else: # Linux, macOS
            command = ["traceroute", "-n", target] # -n to avoid resolving hostnames
            ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b" # Matches standard IPs

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300, # Increased timeout for potentially long traceroutes
                check=True
            )
            raw_output = process.stdout
            
            for line in raw_output.splitlines():
                # Extract all IPs from the line, as some hops might show multiple
                found_ips = re.findall(ip_pattern, line)
                for ip in found_ips:
                    # Basic validation for valid IPv4 range (not perfect, but good enough for common use)
                    parts = list(map(int, ip.split('.')))
                    if all(0 <= p <= 255 for p in parts):
                        hop_ips.append(ip)
            
        except subprocess.CalledProcessError as e:
            raw_output = f"Error running traceroute: {e.stderr}"
            st.error(f"Traceroute command failed: {e.stderr}")
        except subprocess.TimeoutExpired:
            raw_output = "Traceroute command timed out."
            st.error("Traceroute command timed out.")
        except FileNotFoundError:
            raw_output = f"Traceroute command not found. Please ensure 'tracert' (Windows) or 'traceroute' (Linux/macOS) is installed and in your PATH."
            st.error(raw_output)
        except Exception as e:
            raw_output = f"An unexpected error occurred during traceroute: {e}"
            st.error(f"An unexpected error occurred during traceroute: {e}")
            
        return raw_output, list(dict.fromkeys(hop_ips)) # Use dict.fromkeys to preserve order and remove duplicates

    @staticmethod
    def get_hop_locations(hop_ips):
        """
        Performs geolocation lookup for a list of IP addresses.
        Returns a list of dictionaries with 'latitude', 'longitude', and 'ip'.
        """
        locations = []
        if not Config.IPINFO_TOKEN or Config.IPINFO_TOKEN == "YOUR_IPINFO_TOKEN":
            st.warning("IPINFO_TOKEN is not configured. IP geolocation will not work.")
            return []

        for ip in hop_ips:
            geo_info = OSINTUtils.geo_lookup(ip)
            if isinstance(geo_info, dict) and 'error' not in geo_info and geo_info['location'] != '0,0':
                lat, lon = map(float, geo_info['location'].split(','))
                locations.append({
                    "latitude": lat,
                    "longitude": lon,
                    "ip": ip,
                    "city": geo_info.get('city', 'Unknown'),
                    "country": geo_info.get('country', 'Unknown')
                })
        return locations

# --- Port Scanner ---
class PortScanner:
    @staticmethod
    def scan_port(target_host, target_port, timeout=1):
        """
        Attempts to connect to a specific port on a target host.
        Returns True if the port is open, False otherwise.
        """
        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set a timeout for the connection attempt
            s.settimeout(timeout)
            # Attempt to connect to the target host and port
            result = s.connect_ex((target_host, target_port))
            s.close()
            # If result is 0, the connection was successful (port is open)
            if result == 0:
                return True
            else:
                return False
        except socket.gaierror:
            # Hostname resolution error
            return "Hostname could not be resolved."
        except socket.error as e:
            # Other socket-related errors
            return f"Socket error: {e}"
        except Exception as e:
            # Catch any other unexpected errors
            return f"An unexpected error occurred: {e}"

    @staticmethod
    def scan_range(target_host, start_port, end_port):
        """
        Scans a range of ports on a target host.
        Returns a list of open ports.
        """
        open_ports = []
        st.write(f"Scanning ports {start_port}-{end_port} on {target_host}...")
        
        # Get the IP address from the hostname, if a hostname is provided
        try:
            target_ip = socket.gethostbyname(target_host)
        except socket.gaierror:
            st.error(f"Error: Hostname '{target_host}' could not be resolved.")
            return []

        # Create a progress bar for the scan
        progress_text = "Scanning in progress. Please wait."
        my_bar = st.progress(0, text=progress_text)
        
        total_ports = end_port - start_port + 1
        
        for i, port in enumerate(range(start_port, end_port + 1)):
            status = PortScanner.scan_port(target_ip, port)
            if status is True:
                open_ports.append(port)
            elif isinstance(status, str): # Handle error messages from scan_port
                st.warning(f"Port {port}: {status}") # Display error for specific port
            
            # Update progress bar
            progress_percentage = (i + 1) / total_ports
            my_bar.progress(progress_percentage, text=f"{progress_text} ({int(progress_percentage*100)}%)")
            
        my_bar.empty() # Remove the progress bar after completion
        return open_ports


# --- UI Components ---
# --- IMPORTANT: MainUI is defined BEFORE AuthUI to ensure proper loading ---
class MainUI:
    @staticmethod
    def render_enhanced_map(locations):
        if not locations:
            st.warning("No location data available")
            return
        
        st.subheader("🌍 Enhanced Location Visualization")
        tab1, tab2, tab3 = st.tabs(["Interactive Map", "Timeline", "Heatmap"])
        
        with tab1:
            first_loc = locations[0]
            m = folium.Map(
                location=[first_loc["latitude"], first_loc["longitude"]],
                zoom_start=10,
                tiles="OpenStreetMap"
            )
            for loc in locations:
                folium.Marker(
                    [loc["latitude"], loc["longitude"]],
                    popup=f"Time: {loc.get('timestamp', 'N/A')}<br>IP: {loc.get('ip', 'N/A')}<br>City: {loc.get('city', 'N/A')}",
                    tooltip=f"Lat: {loc['latitude']}, Lon: {loc['longitude']}"
                ).add_to(m)
            folium.PolyLine(
                [[loc["latitude"], loc["longitude"]] for loc in locations],
                color="blue",
                weight=2.5,
                opacity=1
            ).add_to(m)
            folium_static(m, width=800, height=500)
        
        with tab2:
            df = pd.DataFrame(locations)
            # Ensure 'timestamp' column exists before converting
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                if df['timestamp'].isnull().all():
                    st.warning("No valid timestamps found for timeline.")
                else:
                    st.line_chart(
                        df.set_index('timestamp')[['latitude', 'longitude']],
                        use_container_width=True
                    )
            else:
                st.warning("No timestamp data available for timeline.")
        
        with tab3:
            m = folium.Map(
                location=[first_loc["latitude"], first_loc["longitude"]],
                zoom_start=10,
                tiles="OpenStreetMap"
            )
            from folium.plugins import HeatMap
            HeatMap(
                [[loc["latitude"], loc["longitude"]] for loc in locations],
                radius=15
            ).add_to(m)
            folium_static(m, width=800, height=500)

    @staticmethod
    def render_network_analysis(network_data):
        if not network_data:
            st.warning("No network data available for analysis")
            return
        
        st.subheader("🕸️ Network Traffic Analysis")
        
        if "IP Analysis" in network_data and network_data["IP Analysis"]:
            st.markdown("### 🌐 IP Address Analysis")
            ip_df = pd.DataFrame(network_data["IP Analysis"])
            
            # Filter valid coordinates
            valid_coords = [
                row for row in network_data["IP Analysis"]
                if isinstance(row.get('Coordinates'), str) and 
                   ',' in row['Coordinates'] and 
                   len(row['Coordinates'].split(',')) == 2 and
                   all(
                       x.replace('.', '', 1).replace('-', '', 1).isdigit()
                       for x in row['Coordinates'].split(',')
                   ) and
                   row['Coordinates'] != '0,0'
            ]
            
            if valid_coords:
                try:
                    valid_df = pd.DataFrame(valid_coords)
                    first_coords = valid_coords[0]['Coordinates'].split(',')
                    latitude = float(first_coords[0])
                    longitude = float(first_coords[1])
                    
                    valid_df['latitude'] = valid_df['Coordinates'].apply(lambda x: float(x.split(',')[0]))
                    valid_df['longitude'] = valid_df['Coordinates'].apply(lambda x: float(x.split(',')[1]))
                    
                    st.pydeck_chart(pdk.Deck(
                        map_style='mapbox://styles/mapbox/light-v9',
                        initial_view_state=pdk.ViewState(
                            latitude=latitude,
                            longitude=longitude,
                            zoom=1,
                            pitch=0,
                        ),
                        layers=[
                            pdk.Layer(
                                'ScatterplotLayer',
                                data=valid_df,
                                get_position='[longitude, latitude]',
                                get_color='[200, 30, 0, 160]',
                                get_radius=200000,
                                pickable=True
                            )
                        ],
                        tooltip={
                            "html": "<b>IP:</b> {IP}<br><b>Location:</b> {Location}<br><b>Org:</b> {Organization}",
                            "style": {"color": "white"}
                        }
                    ))
                except Exception as e:
                    st.error(f"Failed to render IP map: {str(e)}")
            else:
                st.warning("No valid coordinates available for IP mapping")
            
            st.dataframe(
                ip_df.drop(columns=['Coordinates'], errors='ignore'),
                use_container_width=True
            )
        else:
            st.warning("No valid IP address data available for analysis")
        
        if "Domain Analysis" in network_data:
            st.markdown("### 🔗 Domain Analysis")
            for domain_info in network_data["Domain Analysis"]:
                with st.expander(f"Domain: {domain_info['Domain']}"):
                    for record_type, records in domain_info["DNS Records"].items():
                        st.markdown(f"**{record_type} Records:**")
                        if isinstance(records, list):
                            for r in records:
                                st.code(r, language='text')
                        else:
                            st.code(records, language='text')

    @staticmethod
    def render_malware_scanner():
        st.subheader("Malware Signature Scanner")
        st.write("Upload a file to calculate its SHA256 hash and scan its content for known malicious signatures.")
        

        # Button to simulate updating signatures
        if st.button("Update Malware Signatures (Simulated)"):
            new_hashes_count = MalwareScanner.update_known_hashes()
            st.success(f"Simulated update complete! Added {new_hashes_count} new signatures.")
            st.info(f"Total signatures now: {len(st.session_state.known_malicious_hashes)}")


        uploaded_file = st.file_uploader("Upload a file for scanning", type=None) # Allow any file type

        if uploaded_file:
            st.markdown("---")
            st.write(f"**File Name:** `{uploaded_file.name}`")
            st.write(f"**File Type:** `{uploaded_file.type}`")
            st.write(f"**File Size:** `{uploaded_file.size / 1024:.2f} KB`")

            file_content = uploaded_file.read()
            
            # Calculate SHA256 hash
            file_hash = MalwareScanner.calculate_sha256(file_content)
            st.write(f"**SHA256 Hash:** `{file_hash}`")

            # Check hash against known malicious hashes (from session state)
            if file_hash in st.session_state.known_malicious_hashes:
                st.error(f"🚨 **Known Malicious Hash Detected!**")
                st.error(f"Reason: {st.session_state.known_malicious_hashes[file_hash]}")
                st.session_state.report_results.append(["Malware Scan (Hash)", f"Threat: Known malicious hash ({file_hash}) - {st.session_state.known_malicious_hashes[file_hash]}"])
            else:
                st.success("✅ File hash is not in the known malicious database.")
                st.session_state.report_results.append(["Malware Scan (Hash)", f"No known malicious hash detected for {file_hash}."])

            st.markdown("---")
            st.write("### Content Scan for Threat Patterns")
            try:
                # Attempt to decode content as text for pattern scanning
                text_content = file_content.decode("utf-8", errors='ignore')
                content_threats = MalwareScanner.scan_file_content(text_content)

                if content_threats:
                    st.warning(f"⚠️ **{len(content_threats)} potential threat patterns found in file content!**")
                    for label, value in content_threats:
                        st.write(f"🔸 **{label}:** `{value}`")
                        st.session_state.report_results.append(["Malware Scan (Content)", f"Threat: {label}: {value}"])
                else:
                    st.info("No common threat patterns detected in file content.")
                    st.session_state.report_results.append(["Malware Scan (Content)", "No common threat patterns detected."])

            except Exception as e:
                st.warning(f"Could not decode file content for text-based scanning (e.g., it might be a binary file). Error: {e}")
                st.session_state.report_results.append(["Malware Scan (Content)", f"Could not scan content: {e}"])
            
            st.markdown("---")
            st.info("Results added to the Analysis Report tab.")

# --- Traceroute Analyzer ---
class TracerouteAnalyzer:
    @staticmethod
    def run_traceroute(target):
        """
        Runs traceroute/tracert command and parses the output to extract hop IPs.
        Returns raw output and a list of IP addresses for each hop.
        """
        raw_output = ""
        hop_ips = []
        
        if sys.platform.startswith('win'):
            command = ["tracert", "-d", target] # -d to avoid resolving hostnames
            ip_pattern = r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?" # Matches IPs in brackets or not
        else: # Linux, macOS
            command = ["traceroute", "-n", target] # -n to avoid resolving hostnames
            ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b" # Matches standard IPs

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300, # Increased timeout for potentially long traceroutes
                check=True
            )
            raw_output = process.stdout
            
            for line in raw_output.splitlines():
                # Extract all IPs from the line, as some hops might show multiple
                found_ips = re.findall(ip_pattern, line)
                for ip in found_ips:
                    # Basic validation for valid IPv4 range (not perfect, but good enough for common use)
                    parts = list(map(int, ip.split('.')))
                    if all(0 <= p <= 255 for p in parts):
                        hop_ips.append(ip)
            
        except subprocess.CalledProcessError as e:
            raw_output = f"Error running traceroute: {e.stderr}"
            st.error(f"Traceroute command failed: {e.stderr}")
        except subprocess.TimeoutExpired:
            raw_output = "Traceroute command timed out."
            st.error("Traceroute command timed out.")
        except FileNotFoundError:
            raw_output = f"Traceroute command not found. Please ensure 'tracert' (Windows) or 'traceroute' (Linux/macOS) is installed and in your PATH."
            st.error(raw_output)
        except Exception as e:
            raw_output = f"An unexpected error occurred during traceroute: {e}"
            st.error(f"An unexpected error occurred during traceroute: {e}")
            
        return raw_output, list(dict.fromkeys(hop_ips)) # Use dict.fromkeys to preserve order and remove duplicates

    @staticmethod
    def get_hop_locations(hop_ips):
        """
        Performs geolocation lookup for a list of IP addresses.
        Returns a list of dictionaries with 'latitude', 'longitude', and 'ip'.
        """
        locations = []
        if not Config.IPINFO_TOKEN or Config.IPINFO_TOKEN == "YOUR_IPINFO_TOKEN":
            st.warning("IPINFO_TOKEN is not configured. IP geolocation will not work.")
            return []

        for ip in hop_ips:
            geo_info = OSINTUtils.geo_lookup(ip)
            if isinstance(geo_info, dict) and 'error' not in geo_info and geo_info['location'] != '0,0':
                lat, lon = map(float, geo_info['location'].split(','))
                locations.append({
                    "latitude": lat,
                    "longitude": lon,
                    "ip": ip,
                    "city": geo_info.get('city', 'Unknown'),
                    "country": geo_info.get('country', 'Unknown')
                })
        return locations

# --- Port Scanner ---
class PortScanner:
    @staticmethod
    def scan_port(target_host, target_port, timeout=1):
        """
        Attempts to connect to a specific port on a target host.
        Returns True if the port is open, False otherwise.
        """
        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set a timeout for the connection attempt
            s.settimeout(timeout)
            # Attempt to connect to the target host and port
            result = s.connect_ex((target_host, target_port))
            s.close()
            # If result is 0, the connection was successful (port is open)
            if result == 0:
                return True
            else:
                return False
        except socket.gaierror:
            # Hostname resolution error
            return "Hostname could not be resolved."
        except socket.error as e:
            # Other socket-related errors
            return f"Socket error: {e}"
        except Exception as e:
            # Catch any other unexpected errors
            return f"An unexpected error occurred: {e}"

    @staticmethod
    def scan_range(target_host, start_port, end_port):
        """
        Scans a range of ports on a target host.
        Returns a list of open ports.
        """
        open_ports = []
        st.write(f"Scanning ports {start_port}-{end_port} on {target_host}...")
        
        # Get the IP address from the hostname, if a hostname is provided
        try:
            target_ip = socket.gethostbyname(target_host)
        except socket.gaierror:
            st.error(f"Error: Hostname '{target_host}' could not be resolved.")
            return []

        # Create a progress bar for the scan
        progress_text = "Scanning in progress. Please wait."
        my_bar = st.progress(0, text=progress_text)
        
        total_ports = end_port - start_port + 1
        
        for i, port in enumerate(range(start_port, end_port + 1)):
            status = PortScanner.scan_port(target_ip, port)
            if status is True:
                open_ports.append(port)
            elif isinstance(status, str): # Handle error messages from scan_port
                st.warning(f"Port {port}: {status}") # Display error for specific port
            
            # Update progress bar
            progress_percentage = (i + 1) / total_ports
            my_bar.progress(progress_percentage, text=f"{progress_text} ({int(progress_percentage*100)}%)")
            
        my_bar.empty() # Remove the progress bar after completion
        return open_ports


# --- UI Components ---
# --- IMPORTANT: MainUI is defined BEFORE AuthUI to ensure proper loading ---
class MainUI:
    @staticmethod
    def render_enhanced_map(locations):
        if not locations:
            st.warning("No location data available")
            return
        
        st.subheader("🌍 Enhanced Location Visualization")
        tab1, tab2, tab3 = st.tabs(["Interactive Map", "Timeline", "Heatmap"])
        
        with tab1:
            first_loc = locations[0]
            m = folium.Map(
                location=[first_loc["latitude"], first_loc["longitude"]],
                zoom_start=10,
                tiles="OpenStreetMap"
            )
            for loc in locations:
                folium.Marker(
                    [loc["latitude"], loc["longitude"]],
                    popup=f"Time: {loc.get('timestamp', 'N/A')}<br>IP: {loc.get('ip', 'N/A')}<br>City: {loc.get('city', 'N/A')}",
                    tooltip=f"Lat: {loc['latitude']}, Lon: {loc['longitude']}"
                ).add_to(m)
            folium.PolyLine(
                [[loc["latitude"], loc["longitude"]] for loc in locations],
                color="blue",
                weight=2.5,
                opacity=1
            ).add_to(m)
            folium_static(m, width=800, height=500)
        
        with tab2:
            df = pd.DataFrame(locations)
            # Ensure 'timestamp' column exists before converting
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                if df['timestamp'].isnull().all():
                    st.warning("No valid timestamps found for timeline.")
                else:
                    st.line_chart(
                        df.set_index('timestamp')[['latitude', 'longitude']],
                        use_container_width=True
                    )
            else:
                st.warning("No timestamp data available for timeline.")
        
        with tab3:
            m = folium.Map(
                location=[first_loc["latitude"], first_loc["longitude"]],
                zoom_start=10,
                tiles="OpenStreetMap"
            )
            from folium.plugins import HeatMap
            HeatMap(
                [[loc["latitude"], loc["longitude"]] for loc in locations],
                radius=15
            ).add_to(m)
            folium_static(m, width=800, height=500)

    @staticmethod
    def render_network_analysis(network_data):
        if not network_data:
            st.warning("No network data available for analysis")
            return
        
        st.subheader("🕸️ Network Traffic Analysis")
        
        if "IP Analysis" in network_data and network_data["IP Analysis"]:
            st.markdown("### 🌐 IP Address Analysis")
            ip_df = pd.DataFrame(network_data["IP Analysis"])
            
            # Filter valid coordinates
            valid_coords = [
                row for row in network_data["IP Analysis"]
                if isinstance(row.get('Coordinates'), str) and 
                   ',' in row['Coordinates'] and 
                   len(row['Coordinates'].split(',')) == 2 and
                   all(
                       x.replace('.', '', 1).replace('-', '', 1).isdigit()
                       for x in row['Coordinates'].split(',')
                   ) and
                   row['Coordinates'] != '0,0'
            ]
            
            if valid_coords:
                try:
                    valid_df = pd.DataFrame(valid_coords)
                    first_coords = valid_coords[0]['Coordinates'].split(',')
                    latitude = float(first_coords[0])
                    longitude = float(first_coords[1])
                    
                    valid_df['latitude'] = valid_df['Coordinates'].apply(lambda x: float(x.split(',')[0]))
                    valid_df['longitude'] = valid_df['Coordinates'].apply(lambda x: float(x.split(',')[1]))
                    
                    st.pydeck_chart(pdk.Deck(
                        map_style='mapbox://styles/mapbox/light-v9',
                        initial_view_state=pdk.ViewState(
                            latitude=latitude,
                            longitude=longitude,
                            zoom=1,
                            pitch=0,
                        ),
                        layers=[
                            pdk.Layer(
                                'ScatterplotLayer',
                                data=valid_df,
                                get_position='[longitude, latitude]',
                                get_color='[200, 30, 0, 160]',
                                get_radius=200000,
                                pickable=True
                            )
                        ],
                        tooltip={
                            "html": "<b>IP:</b> {IP}<br><b>Location:</b> {Location}<br><b>Org:</b> {Organization}",
                            "style": {"color": "white"}
                        }
                    ))
                except Exception as e:
                    st.error(f"Failed to render IP map: {str(e)}")
            else:
                st.warning("No valid coordinates available for IP mapping")
            
            st.dataframe(
                ip_df.drop(columns=['Coordinates'], errors='ignore'),
                use_container_width=True
            )
        else:
            st.warning("No valid IP address data available for analysis")
        
        if "Domain Analysis" in network_data:
            st.markdown("### 🔗 Domain Analysis")
            for domain_info in network_data["Domain Analysis"]:
                with st.expander(f"Domain: {domain_info['Domain']}"):
                    for record_type, records in domain_info["DNS Records"].items():
                        st.markdown(f"**{record_type} Records:**")
                        if isinstance(records, list):
                            for r in records:
                                st.code(r, language='text')
                        else:
                            st.code(records, language='text')

    @staticmethod
    def render_malware_scanner():
        st.subheader("Malware Signature Scanner")
        st.write("Upload a file to calculate its SHA256 hash and scan its content for known malicious signatures.")
        

        # Button to simulate updating signatures
        if st.button("Update Malware Signatures (Simulated)"):
            new_hashes_count = MalwareScanner.update_known_hashes()
            st.success(f"Simulated update complete! Added {new_hashes_count} new signatures.")
            st.info(f"Total signatures now: {len(st.session_state.known_malicious_hashes)}")


        uploaded_file = st.file_uploader("Upload a file for scanning", type=None) # Allow any file type

        if uploaded_file:
            st.markdown("---")
            st.write(f"**File Name:** `{uploaded_file.name}`")
            st.write(f"**File Type:** `{uploaded_file.type}`")
            st.write(f"**File Size:** `{uploaded_file.size / 1024:.2f} KB`")

            file_content = uploaded_file.read()
            
            # Calculate SHA256 hash
            file_hash = MalwareScanner.calculate_sha256(file_content)
            st.write(f"**SHA256 Hash:** `{file_hash}`")

            # Check hash against known malicious hashes (from session state)
            if file_hash in st.session_state.known_malicious_hashes:
                st.error(f"🚨 **Known Malicious Hash Detected!**")
                st.error(f"Reason: {st.session_state.known_malicious_hashes[file_hash]}")
                st.session_state.report_results.append(["Malware Scan (Hash)", f"Threat: Known malicious hash ({file_hash}) - {st.session_state.known_malicious_hashes[file_hash]}"])
            else:
                st.success("✅ File hash is not in the known malicious database.")
                st.session_state.report_results.append(["Malware Scan (Hash)", f"No known malicious hash detected for {file_hash}."])

            st.markdown("---")
            st.write("### Content Scan for Threat Patterns")
            try:
                # Attempt to decode content as text for pattern scanning
                text_content = file_content.decode("utf-8", errors='ignore')
                content_threats = MalwareScanner.scan_file_content(text_content)

                if content_threats:
                    st.warning(f"⚠️ **{len(content_threats)} potential threat patterns found in file content!**")
                    for label, value in content_threats:
                        st.write(f"🔸 **{label}:** `{value}`")
                        st.session_state.report_results.append(["Malware Scan (Content)", f"Threat: {label}: {value}"])
                else:
                    st.info("No common threat patterns detected in file content.")
                    st.session_state.report_results.append(["Malware Scan (Content)", "No common threat patterns detected."])

            except Exception as e:
                st.warning(f"Could not decode file content for text-based scanning (e.g., it might be a binary file). Error: {e}")
                st.session_state.report_results.append(["Malware Scan (Content)", f"Could not scan content: {e}"])
            
            st.markdown("---")
            st.info("Results added to the Analysis Report tab.")

    @staticmethod
    def render_traceroute_mapping():
        st.subheader("Traceroute Mapping")
        st.write("Enter an IP address or domain to visualize the network path to it.")

        target = st.text_input("Enter target IP or Domain (e.g., google.com, 8.8.8.8)", key="traceroute_target")

        if st.button("Run Traceroute"):
            if target:
                with st.spinner(f"Running traceroute to {target} (this may take a moment)..."):
                    raw_output, hop_ips = TracerouteAnalyzer.run_traceroute(target)
                    st.session_state.traceroute_hops = [] # Clear previous hops
                    
                    st.markdown("### Raw Traceroute Output")
                    st.code(raw_output, language='bash')

                    if hop_ips:
                        st.info(f"Found {len(hop_ips)} unique IP hops.")
                        with st.spinner("Performing geolocation for hops..."):
                            hop_locations = TracerouteAnalyzer.get_hop_locations(hop_ips)
                            st.session_state.traceroute_hops = hop_locations
                            st.success(f"Successfully geolocated {len(hop_locations)} hops.")
                            
                            if hop_locations:
                                st.markdown("### Network Path Visualization")
                                # Center map on the first hop, or a default if no hops are geolocated
                                initial_location = [hop_locations[0]['latitude'], hop_locations[0]['longitude']] if hop_locations else [0, 0]
                                m = folium.Map(location=initial_location, zoom_start=2)

                                # Add markers for each hop
                                for i, hop in enumerate(hop_locations):
                                    folium.Marker(
                                        [hop['latitude'], hop['longitude']],
                                        popup=f"Hop {i+1}: {hop['ip']}<br>City: {hop['city']}<br>Country: {hop['country']}",
                                        tooltip=f"Hop {i+1}: {hop['ip']}"
                                    ).add_to(m)

                                # Draw lines between consecutive hops
                                if len(hop_locations) > 1:
                                    points = [[hop['latitude'], hop['longitude']] for hop in hop_locations]
                                    folium.PolyLine(points, color="red", weight=2.5, opacity=0.8).add_to(m)
                                
                                folium_static(m, width=800, height=500)

                                st.markdown("### Hop Details")
                                hop_df = pd.DataFrame(hop_locations)
                                st.dataframe(hop_df[['ip', 'city', 'country', 'latitude', 'longitude']], use_container_width=True)
                            else:
                                st.warning("Could not geolocate any hops or no hops found.")
                    else:
                        st.warning("No IP addresses found in traceroute output.")
            else:
                st.warning("Please enter a target IP or Domain.")

    @staticmethod
    def render_port_scanner():
        st.subheader("Port Scanner")
        st.write("Scan a target IP address or domain for open TCP ports.")

        target_host = st.text_input("Target Host (IP or Domain, e.g., scanme.nmap.org, 127.0.0.1)", key="port_scan_target_host")
        col1, col2 = st.columns(2)
        with col1:
            start_port = st.number_input("Start Port", min_value=1, max_value=65535, value=1, key="port_scan_start_port")
        with col2:
            end_port = st.number_input("End Port", min_value=1, max_value=65535, value=1024, key="port_scan_end_port")

        if st.button("Scan Ports"):
            if target_host and start_port <= end_port:
                with st.spinner(f"Scanning ports {start_port}-{end_port} on {target_host}..."):
                    st.session_state.port_scan_results = [] # Clear previous results
                    open_ports = PortScanner.scan_range(target_host, start_port, end_port)
                    st.session_state.port_scan_results = open_ports
                    
                    if open_ports:
                        st.success(f"Scan complete! Found {len(open_ports)} open port(s).")
                        st.markdown("### Open Ports:")
                        for port in open_ports:
                            st.write(f"✅ Port {port} is OPEN")
                            st.session_state.report_results.append(["Port Scan", f"Port {port} is OPEN on {target_host}"])
                    else:
                        st.info("No open ports found in the specified range.")
                        st.session_state.report_results.append(["Port Scan", f"No open ports found on {target_host} in range {start_port}-{end_port}."])
            else:
                st.warning("Please enter a valid target host and a valid port range.")
        
        if st.session_state.port_scan_results:
            st.markdown("---")
            st.write("### Previous Scan Results")
            for port in st.session_state.port_scan_results:
                st.write(f"✅ Port {port} was found OPEN.")


    @staticmethod
    def render():
        st.set_page_config(page_title="Android Threat Notepad + OSINT", layout="wide")
        st.title("Shadow Sweep 🔍")
        st.write(f"Welcome, {st.session_state.username}!")
        
        with st.sidebar:
            st.subheader("Connection Status")
            if st.button("Check Tor Connection"):
                if SecurityUtils.test_tor_connection():
                    st.success("✅ Tor is connected!")
                else:
                    st.error("❌ Tor connection failed")
            if st.session_state.tor_status:
                st.success("Tor: Connected")
            else:
                st.warning("Tor: Not connected")
            
            st.subheader("ADB Connection")
            if st.button("🔄 Refresh ADB Devices"):
                st.session_state.adb_devices = ADBUtils.get_connected_devices()
            success, devices = st.session_state.adb_devices
            if success:
                if devices:
                    st.success(f"Connected: {', '.join(devices)}")
                    st.session_state.adb_device = st.selectbox(
                        "Select device",
                        devices,
                        key="adb_device_select"
                    )
                else:
                    st.warning("No devices connected")
            else:
                st.error(devices[0] if devices else "ADB not configured")
            
            st.markdown("---")
            if st.button("Logout"):
                SessionState.logout()
                st.rerun()
        
        # Updated tabs: File Analysis, Dark Web Scan, Malware Signature Scanner, Traceroute Mapping, Port Scanner
        tab1, tab2, tab3, tab4, tab5 = st.tabs(["File Analysis", "Dark Web Scan", "Malware Signature Scanner", "Traceroute Mapping", "Port Scanner"])
        
        with tab1:
            MainUI.render_file_analysis()
        
        with tab2:
            MainUI.render_darkweb_scan()
            
        with tab3:
            MainUI.render_malware_scanner()
        
        with tab4:
            MainUI.render_traceroute_mapping()

        with tab5: # New tab for Port Scanner
            MainUI.render_port_scanner()


    @staticmethod
    def render_file_analysis():
        st.subheader("File Analysis")
        uploaded_file = st.file_uploader("Upload log file", type=["txt", "log", "json", "xml"], key="file_analysis_uploader")
        text = ""
        
        if uploaded_file:
            text = uploaded_file.read().decode("utf-8", errors='ignore')
            st.text_area("Log Content", text, height=300, key="log_content")
        elif st.session_state.get("logs_pulled"):
            log_path = os.path.join("adb_logs", "logcat.txt")
            if os.path.exists(log_path):
                with open(log_path, "r", encoding='utf-8') as f:
                    text = f.read()
                st.text_area("Log Content", text, height=300, key="log_content")
        
        with st.expander("Pull Device Logs"):
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Test ADB Connection"):
                    st.session_state.adb_devices = ADBUtils.get_connected_devices()
                    st.rerun()
            with col2:
                if st.button("Pull Logs", key="pull_logs_btn"):
                    device_id = st.session_state.get("adb_device")
                    with st.spinner("Collecting logs (may take 1-2 minutes)..."):
                        success, message = ADBUtils.pull_logs(
                            device_id=device_id,
                            timeout=120
                        )
                        if success:
                            st.success(message)
                            st.session_state.logs_pulled = True
                            st.rerun()
                        else:
                            st.error(message)
            
            if st.session_state.get("logs_pulled"):
                log_path = os.path.join("adb_logs", "logcat.txt")
                if os.path.exists(log_path):
                    with open(log_path, "r", encoding='utf-8') as f:
                        log_content = f.read()
                    st.download_button(
                        "Download Logs",
                        log_content,
                        file_name="device_logs.txt"
                    )
        
        if text:
            st.markdown("### Android & OSINT Checks")
            all_options = st.checkbox("✅ All checks", key="all_options")
            
            cols = st.columns(2)
            with cols[0]:
                chk_hidden_apps = st.checkbox("🔒 Hidden Apps", value=all_options, key="chk_hidden_apps")
                chk_perms = st.checkbox("🛡️ Dangerous Permissions", value=all_options, key="chk_perms")
                chk_phishing_sms = st.checkbox("📨 Phishing SMS", value=all_options, key="chk_phishing_sms")
                chk_adb = st.checkbox("🔌 ADB Commands", value=all_options, key="chk_adb")
                chk_gps = st.checkbox("📍 GPS Locations", value=all_options, key="chk_gps")
                # New checkbox for Unusual Protocols
                chk_unusual_protocol = st.checkbox("📡 Unusual Protocols", value=all_options, key="chk_unusual_protocol")
            
            with cols[1]:
                chk_whois = st.checkbox("🌐 WHOIS Lookup", value=all_options, key="chk_whois")
                chk_ip_lookup = st.checkbox("📍 IP Lookup", value=all_options, key="chk_ip_lookup")
                chk_ports = st.checkbox("🛠️ Open Ports", value=all_options, key="chk_ports")
                chk_email_headers = st.checkbox("📧 Email Headers", value=all_options, key="chk_email_headers")
                chk_network = st.checkbox("🕸️ Network Analysis", value=all_options, key="chk_network")
            
            if st.button("Analyze Log File"):
                with st.spinner("Analyzing..."):
                    current_file_results = []
                    
                    if chk_hidden_apps or all_options:
                        found_apps = ThreatDetector.detect_hidden_apps(text)
                        current_file_results.extend([["Hidden App", app] for app in found_apps] if found_apps else [["Hidden App", "None found"]])
                    
                    if chk_perms or all_options:
                        found_perms = ThreatDetector.detect_permissions(text)
                        current_file_results.append(["Permissions", ", ".join(found_perms)] if found_perms else [["Permissions", "None found"]])
                    
                    if chk_phishing_sms or all_options:
                        found_sms = ThreatDetector.detect_spoofed_sms(text)
                        current_file_results.extend([["Phishing SMS", sms] for sms in found_sms] if found_sms else [["Phishing SMS", "None found"]])
                    
                    if chk_adb or all_options:
                        current_file_results.append(["ADB Usage", "Detected"] if ThreatDetector.detect_adb_usage(text) else ["ADB Usage", "Not detected"])
                    
                    if chk_gps or all_options:
                        found_locs = ThreatDetector.extract_locations(text)
                        if found_locs:
                            current_file_results.extend([["GPS Location", f"Lat: {loc['latitude']}, Lon: {loc['longitude']}"] for loc in found_locs])
                            st.session_state.locations_data = found_locs
                        else:
                            current_file_results.append(["GPS Location", "None found"])
                    
                    if chk_whois or all_options:
                        domains = ThreatDetector.detect_dns_queries(text)
                        current_file_results.extend([["WHOIS", f"{domain}: {OSINTUtils.perform_whois(domain)}"] for domain in domains] if domains else [["WHOIS", "No domains found"]])
                    
                    if chk_ip_lookup or all_options:
                        ips = ThreatDetector.detect_ip_addresses(text)
                        current_file_results.extend([["IP Geolocation", f"{ip}: {OSINTUtils.geo_lookup(ip)}"] for ip in ips] if ips else [["IP Geolocation", "No IPs found"]])
                    
                    if chk_ports or all_options:
                        ports_found = ThreatDetector.detect_ports(text)
                        current_file_results.append(["Open Ports", ports_found] if ports_found else [["Open Ports", "None found"]])
                    
                    if chk_email_headers or all_options:
                        email_header_found = ThreatDetector.extract_email_headers(text)
                        current_file_results.append(["Email Header", email_header_found] if email_header_found else [["Email Header", "None found"]])
                    
                    if chk_network or all_options:
                        network_data = NetworkAnalyzer.analyze_network_traffic(text)
                        if network_data:
                            st.session_state.network_data = network_data
                        else:
                            st.info("No network data found for analysis")

                    # New: Unusual Protocol check
                    if chk_unusual_protocol or all_options:
                        unusual_protocols = re.findall(Config.THREAT_PATTERNS["Unusual Protocol"], text)
                        if unusual_protocols:
                            current_file_results.extend([["Unusual Protocol", proto] for proto in set(unusual_protocols)])
                        else:
                            current_file_results.append(["Unusual Protocol", "None found"])
                    
                    st.session_state.report_results = current_file_results
                    st.success(f"Analysis complete! Found {len(current_file_results)} items.")
                    st.rerun()
        
        # Show maps and visualizations after analysis
        if hasattr(st.session_state, 'locations_data') and st.session_state.locations_data:
            MainUI.render_enhanced_map(st.session_state.locations_data)
        
        if hasattr(st.session_state, 'network_data') and st.session_state.network_data:
            MainUI.render_network_analysis(st.session_state.network_data)
        
        if 'report_results' in st.session_state and st.session_state.report_results:
            st.subheader("Analysis Report")
            try:
                data = []
                for item in st.session_state.report_results:
                    if isinstance(item, (list, tuple)) and len(item) >= 2:
                        data.append((item[0], item[1]))
                    else:
                        data.append(("Combined Result", str(item)))
                
                df = pd.DataFrame(data, columns=["Category", "Details"])
                st.dataframe(df, use_container_width=True)
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.download_button(
                        "📥 Download CSV",
                        df.to_csv(index=False).encode("utf-8"),
                        "threat_report.csv",
                        "text/csv"
                    )
                
                with col2:
                    st.download_button(
                        "📥 Download JSON",
                        json.dumps(data, indent=2).encode("utf-8"),
                        "threat_report.json",
                        "application/json"
                    )
                
                with col3:
                    if st.button("generate pdf"):
                        with st.spinner("Generating PDF..."):
                            try:
                                # Create PDF in memory
                                pdf = PDFReport()
                                pdf.generate_report(st.session_state.username, data)
                                
                                # Save to bytes buffer
                                pdf_bytes = BytesIO()
                                pdf.output(pdf_bytes)
                                pdf_bytes.seek(0)
                                
                                # Create download button
                                st.download_button(
                                    "✅ Download PDF",
                                    data=pdf_bytes,
                                    file_name="android_threat_report.pdf",
                                    mime="application/pdf"
                                )
                            except Exception as e:
                                st.error(f"PDF generation failed: {e}")
            
            except Exception as e:
                st.error(f"Error creating report: {str(e)}")
        
        elif 'report_results' in st.session_state:
            st.info("No analysis results available. Please run an analysis first.")

    @staticmethod
    def render_darkweb_scan():
        st.subheader("Dark Web Scan")
        if not st.session_state.tor_status:
            st.warning("Tor connection required for dark web scanning")
            if st.button("Check Tor Connection"):
                if SecurityUtils.test_tor_connection():
                    st.rerun()
                else:
                    st.error("Could not connect to Tor. Is Tor Browser running?")
            return
        
        darkweb_keyword = st.text_input("Enter search keyword", key="darkweb_keyword")
        
        if st.button("Scan Dark Web"):
            with st.spinner("Searching dark web (may take 2-3 minutes)..."):
                try:
                    results = DarkWebScanner.scan(darkweb_keyword)
                    
                    if 'report_results' not in st.session_state:
                        st.session_state.report_results = []
                    
                    for line in results:
                        st.write(line)
                        if isinstance(line, str) and (line.startswith("✅") or line.startswith("🔸")):
                            st.session_state.report_results.append(["Dark Web", line])
                    
                    if not results:
                        st.warning("No results found")
                
                except Exception as e:
                    st.error(f"Scan failed: {str(e)}")

# --- AuthUI is defined after MainUI now ---
class AuthUI:
    @staticmethod
    def render():
        st.set_page_config(page_title="Login - Android Threat Notepad", layout="centered")
        st.title("Login to Shadow Sweep")
        tab1, tab2, tab3 = st.tabs(["Login", "Register", "Forgot Password"])
        with tab1:
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                if st.form_submit_button("Login"):
                    if UserManager.verify_user(username, password):
                        st.session_state.authenticated = True
                        st.session_state.username = username
                        st.session_state.page = 'main'
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        st.error("Invalid username or password.")
        with tab2:
            with st.form("register_form"):
                new_username = st.text_input("New Username", key="reg_username")
                new_password = st.text_input("New Password", type="password", key="reg_password")
                email = st.text_input("Email", key="reg_email")
                if st.form_submit_button("Register"):
                    success, message = UserManager.register_user(new_username, new_password, email)
                    if success:
                        st.success(message)
                    else:
                        st.error(message)
        with tab3:
            with st.form("forgot_password_form"):
                forgot_username = st.text_input("Username", key="forgot_username")
                if st.form_submit_button("Reset Password"):
                    success, temp_password, email = UserManager.reset_password(forgot_username)
                    if success:
                        st.success(f"Temporary password generated: **{temp_password}**")
                        st.info(f"In a real app, this would be sent to: {email}")
                    else:
                        st.error("Username not found.")

# --- Application Entry Point ---
def main():
    SessionState.initialize()
    SessionState.check_timeout()
    
    if not st.session_state.authenticated:
        AuthUI.render()
    else:
        # Diagnostic print to check MainUI before calling render
        # This will appear in your terminal where you run streamlit
        print(f"DEBUG: Type of MainUI: {type(MainUI)}")
        print(f"DEBUG: MainUI has render attribute: {'render' in dir(MainUI)}")
        MainUI.render()

if __name__ == "__main__":
    main()
