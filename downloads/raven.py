#!/usr/bin/env python3
# Raven — Advanced OSINT Framework
# Templar Studios — GPL v3.0
# 
# A comprehensive open-source intelligence gathering tool.
# Modules: Username Search, Email Breach, Domain Intel, Port Scan,
#          Metadata Extraction, IP Geolocation, Phone Lookup,
#          Report Generation, CSV/JSON Export, Caching.

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import json
import os
import re
import csv
import hashlib
import base64
import socket
import ssl
import subprocess
import platform
import sys
import webbrowser
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Tuple, Dict, Any, Callable
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, quote, unquote
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional imports — gracefully degrade if missing
try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import zipfile
    HAS_ZIP = True
except ImportError:
    HAS_ZIP = False

# ──────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────
CONFIG_PATH = Path.home() / '.raven_config.json'
REPORTS_DIR = Path.home() / 'raven_reports'
CACHE_DIR = Path.home() / '.raven_cache'
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

COLORS = {
    'bg': '#0a0a12',
    'card': '#15152a',
    'accent': '#9b30ff',
    'accent2': '#ff1744',
    'text': '#ffffff',
    'dim': '#a0a0b0',
    'success': '#00e676',
    'danger': '#ff4444',
    'warning': '#ffd700',
    'info': '#82aaff'
}

# ──────────────────────────────────────────────
# DATA CLASSES
# ──────────────────────────────────────────────
@dataclass
class SearchResult:
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = ''
    query: str = ''
    data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class UsernameResult(SearchResult):
    platform: str = ''
    found: bool = False
    url: str = ''
    status_code: int = 0
    response_time: float = 0.0
    profile_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EmailResult(SearchResult):
    email: str = ''
    breached: bool = False
    breach_count: int = 0
    breaches: List[Dict] = field(default_factory=list)

@dataclass
class DomainResult(SearchResult):
    domain: str = ''
    registrar: str = ''
    creation_date: str = ''
    expiry_date: str = ''
    nameservers: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    ssl_info: Dict = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)

@dataclass
class NetworkResult(SearchResult):
    target: str = ''
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    banners: Dict[int, str] = field(default_factory=dict)

@dataclass
class PhoneResult(SearchResult):
    phone: str = ''
    valid: bool = False
    country_code: str = ''
    national_number: str = ''
    carrier: str = ''
    timezone: str = ''
    line_type: str = ''

# ──────────────────────────────────────────────
# UTILITY FUNCTIONS
# ──────────────────────────────────────────────
def human_size(size_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f'{size_bytes:.2f} {unit}'
        size_bytes /= 1024
    return f'{size_bytes:.2f} PB'

def get_timestamp() -> str:
    return datetime.now().strftime('%Y%m%d_%H%M%S')

def sha1_hash(data: str) -> str:
    return hashlib.sha1(data.encode()).hexdigest().upper()

def md5_hash(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def clean_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def extract_domain(url: str) -> str:
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.replace('www.', '')
    return domain.split('/')[0].split(':')[0]

# ──────────────────────────────────────────────
# RAVEN ENGINE
# ──────────────────────────────────────────────
class RavenEngine:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        self.running = False
        self.cache = self._load_cache()
        
        # Create directories
        REPORTS_DIR.mkdir(exist_ok=True)
        CACHE_DIR.mkdir(exist_ok=True)

    def _load_cache(self) -> Dict:
        cache_file = CACHE_DIR / 'search_cache.json'
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}

    def _save_cache(self):
        cache_file = CACHE_DIR / 'search_cache.json'
        with open(cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)

    def _get_cached(self, key: str) -> Optional[Any]:
        return self.cache.get(key)

    def _set_cached(self, key: str, value: Any):
        self.cache[key] = value
        self._save_cache()

    # ============================================================
    # USERNAME SEARCH — 50+ PLATFORMS
    # ============================================================
    def search_username(self, username: str, callback: Optional[Callable] = None) -> Dict:
        platforms = {
            'GitHub': f'https://github.com/{username}',
            'Twitter/X': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'TikTok': f'https://tiktok.com/@{username}',
            'YouTube': f'https://youtube.com/@{username}',
            'Twitch': f'https://twitch.tv/{username}',
            'Pinterest': f'https://pinterest.com/{username}',
            'Tumblr': f'https://{username}.tumblr.com',
            'Flickr': f'https://flickr.com/people/{username}',
            'SoundCloud': f'https://soundcloud.com/{username}',
            'DeviantArt': f'https://deviantart.com/{username}',
            'Mastodon': f'https://mastodon.social/@{username}',
            'Discord': f'https://discord.com/users/{username}',
            'Telegram': f'https://t.me/{username}',
            'WhatsApp': f'https://wa.me/{username}',
            'Signal': f'https://signal.org/{username}',
            'Steam': f'https://steamcommunity.com/id/{username}',
            'Roblox': f'https://roblox.com/user.aspx?username={username}',
            'Epic Games': f'https://www.epicgames.com/id/{username}',
            'Xbox': f'https://account.xbox.com/en-us/profile?gamertag={username}',
            'PlayStation': f'https://www.playstation.com/en-us/playstation-network/{username}',
            'Minecraft': f'https://namemc.com/profile/{username}',
            'Chess.com': f'https://www.chess.com/member/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'Medium': f'https://medium.com/@{username}',
            'Behance': f'https://behance.net/{username}',
            'Dribbble': f'https://dribbble.com/{username}',
            'Dev.to': f'https://dev.to/{username}',
            'Stack Overflow': f'https://stackoverflow.com/users/{username}',
            'GitLab': f'https://gitlab.com/{username}',
            'Bitbucket': f'https://bitbucket.org/{username}',
            'Pastebin': f'https://pastebin.com/u/{username}',
            'Keybase': f'https://keybase.io/{username}',
            'WordPress': f'https://{username}.wordpress.com',
            'Blogger': f'https://{username}.blogspot.com',
            'Spotify': f'https://open.spotify.com/user/{username}',
            'Last.fm': f'https://www.last.fm/user/{username}',
            'Goodreads': f'https://www.goodreads.com/{username}',
            'Imgur': f'https://imgur.com/user/{username}',
            'Vimeo': f'https://vimeo.com/{username}',
            'Dailymotion': f'https://www.dailymotion.com/{username}',
            'About.me': f'https://about.me/{username}',
            'AngelList': f'https://angel.co/{username}',
            'ProductHunt': f'https://www.producthunt.com/@{username}',
            'HackerNews': f'https://news.ycombinator.com/user?id={username}',
            'HackerOne': f'https://hackerone.com/{username}',
            'Bugcrowd': f'https://bugcrowd.com/{username}',
            'Codecademy': f'https://www.codecademy.com/profiles/{username}',
            'CodePen': f'https://codepen.io/{username}',
            'Replit': f'https://replit.com/@{username}',
            'Kaggle': f'https://www.kaggle.com/{username}',
            'Patreon': f'https://www.patreon.com/{username}',
            'Ko-fi': f'https://ko-fi.com/{username}',
            'BuyMeACoffee': f'https://www.buymeacoffee.com/{username}',
        }
        
        # Check cache
        cache_key = f'username:{username}'
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        
        results = {}
        total = len(platforms)
        found = 0
        
        # Thread pool for speed
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_platform = {
                executor.submit(self._check_username, platform, url): (platform, url)
                for platform, url in platforms.items()
            }
            
            completed = 0
            for future in as_completed(future_to_platform):
                platform, url = future_to_platform[future]
                try:
                    result = future.result()
                except Exception as e:
                    result = {'exists': False, 'url': url, 'status': 0, 'response_time': 0}
                
                results[platform] = result
                completed += 1
                if result.get('exists'):
                    found += 1
                
                if callback:
                    callback(platform, result, completed, total, found)
        
        final = {
            'username': username,
            'results': results,
            'total_platforms': total,
            'found_count': found,
            'search_time': datetime.now(timezone.utc).isoformat()
        }
        
        self._set_cached(cache_key, final)
        return final

    def _check_username(self, platform: str, url: str) -> Dict:
        start = time.time()
        try:
            resp = self.session.get(url, timeout=8, allow_redirects=True)
            elapsed = time.time() - start
            exists = self._profile_exists(platform, resp)
            result = {
                'exists': exists,
                'url': url,
                'status': resp.status_code,
                'response_time': round(elapsed, 2)
            }
            if exists:
                result['profile_data'] = self._extract_profile_info(resp)
            return result
        except requests.Timeout:
            return {'exists': False, 'url': url, 'status': 0, 'response_time': round(time.time()-start, 2)}
        except requests.ConnectionError:
            return {'exists': False, 'url': url, 'status': 0, 'response_time': round(time.time()-start, 2)}
        except Exception:
            return {'exists': False, 'url': url, 'status': 0, 'response_time': round(time.time()-start, 2)}

    def _profile_exists(self, platform: str, response) -> bool:
        if response.status_code == 404:
            return False
        if response.status_code == 200:
            content = response.text.lower()
            not_found_markers = [
                'not found', 'does not exist', 'page not found',
                'user not found', 'profile not found', 'no user',
                "sorry, this page", "couldn't find", 'this account'
            ]
            for marker in not_found_markers:
                if marker in content:
                    return False
            return True
        return response.status_code not in (403, 410)

    def _extract_profile_info(self, response) -> Dict:
        data = {}
        content = response.text
        
        # Title
        m = re.search(r'<title>(.*?)</title>', content, re.I|re.S)
        if m:
            data['title'] = m.group(1).strip()[:200]
        
        # Meta description
        m = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\'](.*?)["\']', content, re.I|re.S)
        if m:
            data['description'] = m.group(1).strip()[:300]
        
        # Followers/subscribers
        for pattern in [
            r'([\d,]+)\s*followers',
            r'([\d,]+)\s*following',
            r'followers:?\s*([\d,]+)',
            r'([\d,]+)\s*subscribers'
        ]:
            m = re.search(pattern, content, re.I)
            if m:
                data['followers'] = m.group(1)
                break
        
        return data

    # ============================================================
    # EMAIL BREACH CHECK
    # ============================================================
    def check_email_breach(self, email: str) -> Dict:
        email = email.strip().lower()
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return {'valid': False, 'error': 'Invalid email format'}
        
        cache_key = f'email:{email}'
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        
        hibp = self._check_hibp(email)
        breach_patterns = self._check_breach_patterns(email)
        
        result = {
            'valid': True,
            'email': email,
            'hibp': hibp,
            'patterns': breach_patterns,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        self._set_cached(cache_key, result)
        return result

    def _check_hibp(self, email: str) -> Dict:
        email_hash = sha1_hash(email)
        prefix, suffix = email_hash[:5], email_hash[5:]
        try:
            resp = self.session.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=15)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    h, count = line.split(':')
                    if h == suffix:
                        return {'breached': True, 'count': int(count), 'source': 'Have I Been Pwned'}
                return {'breached': False, 'count': 0, 'source': 'Have I Been Pwned'}
            else:
                return {'breached': False, 'count': -1, 'source': 'API Error'}
        except Exception as e:
            return {'breached': False, 'count': -1, 'source': f'Error: {str(e)}'}

    def _check_breach_patterns(self, email: str) -> List[str]:
        patterns = []
        domain = email.split('@')[1]
        known = {'yahoo.com','hotmail.com','aol.com','live.com','myspace.com','linkedin.com','adobe.com','dropbox.com','target.com','equifax.com','experian.com','capitalone.com'}
        if domain in known:
            patterns.append(f'Domain {domain} has known historical breaches')
        username = email.split('@')[0]
        if re.search(r'\d{4}$', username):
            patterns.append('Username ends with 4-digit number (common in compromised accounts)')
        if len(username) < 6:
            patterns.append('Very short username (higher risk)')
        return patterns

    # ============================================================
    # DOMAIN INTELLIGENCE
    # ============================================================
    def get_domain_info(self, domain: str) -> Dict:
        domain = extract_domain(domain)
        cache_key = f'domain:{domain}'
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        
        result = {
            'domain': domain,
            'ip_addresses': [],
            'mx_records': [],
            'txt_records': [],
            'nameservers': [],
            'ssl_info': {},
            'technologies': [],
            'subdomains': []
        }
        
        # DNS queries if available
        if HAS_DNS:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            for rtype, key in [('A', 'ip_addresses'), ('MX', 'mx_records'), ('TXT', 'txt_records'), ('NS', 'nameservers')]:
                try:
                    answers = resolver.resolve(domain, rtype)
                    result[key] = [str(a) for a in answers]
                except:
                    pass
        else:
            try:
                result['ip_addresses'] = [socket.gethostbyname(domain)]
            except:
                pass
        
        # SSL info
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        result['ssl_info'] = {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'version': cert.get('version')
                        }
        except:
            pass
        
        # Technology detection
        result['technologies'] = self._detect_technologies(domain)
        
        # Subdomain enumeration (basic via crt.sh)
        try:
            resp = self.session.get(f'https://crt.sh/?q=%25.{domain}&output=json', timeout=15)
            if resp.status_code == 200:
                subs = set()
                for entry in resp.json():
                    name = entry.get('name_value', '')
                    for n in name.split('\n'):
                        n = n.strip().lower()
                        if n and '*' not in n and n.endswith(domain):
                            subs.add(n)
                result['subdomains'] = sorted(subs)[:50]
        except:
            pass
        
        self._set_cached(cache_key, result)
        return result

    def _detect_technologies(self, domain: str) -> List[str]:
        techs = []
        try:
            resp = self.session.get(f'https://{domain}', timeout=10)
            headers = resp.headers
            content = resp.text[:5000]
            if 'X-Powered-By' in headers:
                techs.append(f"X-Powered-By: {headers['X-Powered-By']}")
            if 'Server' in headers:
                techs.append(f"Server: {headers['Server']}")
            patterns = {
                'React': r'react|_react',
                'Vue.js': r'vue\.js|__vue__',
                'Angular': r'ng-version|angular',
                'jQuery': r'jquery',
                'Bootstrap': r'bootstrap',
                'WordPress': r'wp-content|wordpress',
                'Drupal': r'drupal',
                'Joomla': r'joomla',
                'Laravel': r'laravel',
                'Django': r'django|csrfmiddlewaretoken',
                'Ruby on Rails': r'rails',
                'ASP.NET': r'__VIEWSTATE|asp\.net',
                'PHP': r'\.php|PHPSESSID',
                'Node.js': r'node\.js|express'
            }
            for tech, pat in patterns.items():
                if re.search(pat, content, re.I):
                    techs.append(tech)
        except:
            pass
        return techs

    # ============================================================
    # PORT SCANNER (threaded)
    # ============================================================
    def scan_ports(self, host: str, ports: Optional[List[int]] = None, callback=None) -> Dict:
        if ports is None:
            ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443,9418,27017]
        
        open_ports = []
        results = []
        total = len(ports)
        completed = 0
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self._check_port, host, port): port for port in ports}
            for future in as_completed(futures):
                port = futures[future]
                completed += 1
                try:
                    is_open, service = future.result()
                    if is_open:
                        open_ports.append(port)
                        results.append({'port': port, 'open': True, 'service': service})
                    if callback:
                        callback(port, is_open, completed, total)
                except:
                    pass
        
        return {
            'host': host,
            'ports_scanned': total,
            'open_ports': sorted(open_ports),
            'results': results,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

    def _check_port(self, host: str, port: int) -> Tuple[bool, str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True, self._identify_service(host, port)
            return False, ''
        except:
            return False, ''

    def _identify_service(self, host: str, port: int) -> str:
        common = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',111:'RPC',135:'MS RPC',139:'NetBIOS',143:'IMAP',443:'HTTPS',445:'SMB',993:'IMAPS',995:'POP3S',1723:'PPTP',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC',8080:'HTTP Proxy',8443:'HTTPS Alt',9418:'Git',27017:'MongoDB'}
        service = common.get(port, 'Unknown')
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            if port in (80,443,8080,8443):
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            if banner:
                first = banner.split('\n')[0].strip()
                if first and len(first) < 100:
                    service += f' - {first}'
        except:
            pass
        return service

    # ============================================================
    # METADATA EXTRACTION (ENHANCED)
    # ============================================================
    def extract_metadata(self, filepath: str) -> Dict:
        metadata = {
            'filename': os.path.basename(filepath),
            'path': filepath,
            'size_bytes': 0,
            'size_human': '',
            'extension': '',
            'mime_type': '',
            'file_type': '',
            'created': '',
            'modified': '',
            'accessed': '',
            'hashes': {},
            'strings': [],
            'interesting_strings': [],
            'exif': {},
            'gps': {},
            'pdf_metadata': {},
            'docx_metadata': {}
        }
        try:
            stat = os.stat(filepath)
            metadata['size_bytes'] = stat.st_size
            metadata['size_human'] = human_size(stat.st_size)
            metadata['extension'] = os.path.splitext(filepath)[1].lower()
            metadata['created'] = datetime.fromtimestamp(stat.st_ctime).isoformat()
            metadata['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            metadata['accessed'] = datetime.fromtimestamp(stat.st_atime).isoformat()
            
            with open(filepath, 'rb') as f:
                content = f.read()
            
            metadata['hashes'] = {
                'md5': md5_hash(content),
                'sha1': hashlib.sha1(content).hexdigest(),
                'sha256': sha256_hash(content)
            }
            metadata['mime_type'] = self._detect_mime(content[:16])
            metadata['file_type'] = self._detect_type(content[:16])
            
            strings = self._extract_strings(content)
            metadata['strings'] = strings[:100]
            metadata['interesting_strings'] = [s for s in strings if re.search(r'http|www|@|password|user|key|token|secret|api|db_|admin', s, re.I)][:50]
            
            if HAS_PIL and metadata['extension'] in ('.jpg','.jpeg','.tiff','.png','.gif','.bmp'):
                metadata['exif'] = self._extract_exif(filepath)
                if metadata['exif'].get('GPSInfo'):
                    metadata['gps'] = self._parse_gps(metadata['exif']['GPSInfo'])
            
            if metadata['mime_type'] == 'application/pdf':
                metadata['pdf_metadata'] = self._extract_pdf(content)
            
            if metadata['extension'] == '.docx' and HAS_ZIP:
                metadata['docx_metadata'] = self._extract_docx(filepath)
        except Exception as e:
            metadata['error'] = str(e)
        return metadata

    def _detect_mime(self, header: bytes) -> str:
        mime_map = {
            b'\xff\xd8\xff':'image/jpeg', b'\x89PNG':'image/png', b'GIF87a':'image/gif',
            b'GIF89a':'image/gif', b'%PDF':'application/pdf', b'PK\x03\x04':'application/zip',
            b'\x7fELF':'application/x-elf', b'MZ':'application/x-msdownload', b'RIFF':'audio/wav',
            b'ID3':'audio/mpeg', b'\x1a\x45\xdf\xa3':'video/webm', b'\x00\x00\x00\x18ftyp':'video/mp4'
        }
        for sig, mime in mime_map.items():
            if header.startswith(sig):
                return mime
        return 'application/octet-stream'

    def _detect_type(self, header: bytes) -> str:
        type_map = {
            b'\xff\xd8\xff':'JPEG', b'\x89PNG':'PNG', b'GIF87a':'GIF', b'GIF89a':'GIF',
            b'%PDF':'PDF', b'PK\x03\x04':'ZIP', b'\x7fELF':'ELF', b'MZ':'PE Executable',
            b'RIFF':'WAV', b'ID3':'MP3', b'\x1a\x45\xdf\xa3':'WebM', b'\x00\x00\x00\x18ftyp':'MP4'
        }
        for sig, ftype in type_map.items():
            if header.startswith(sig):
                return ftype
        return 'Unknown'

    def _extract_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        strings, current = [], []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    strings.append(''.join(current))
                current = []
        if len(current) >= min_len:
            strings.append(''.join(current))
        return strings

    def _extract_exif(self, filepath: str) -> Dict:
        try:
            img = Image.open(filepath)
            exif_data = img._getexif()
            if not exif_data:
                return {}
            result = {}
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                result[tag] = str(value)
            return result
        except:
            return {}

    def _parse_gps(self, gps_info) -> Dict:
        # Accept either raw dict or string; simplified
        return {'available': True, 'raw': str(gps_info)}

    def _extract_pdf(self, content: bytes) -> Dict:
        pdf_meta = {}
        for field in ['Title','Author','Subject','Keywords','Creator','Producer','CreationDate','ModDate']:
            fb = field.encode()
            pos = content.find(fb)
            if pos != -1:
                start = pos + len(fb) + 1
                val = content[start:start+200].split(b'\x00')[0].decode('utf-8', errors='ignore').strip('()<>')
                if val:
                    pdf_meta[field] = val
        return pdf_meta

    def _extract_docx(self, filepath: str) -> Dict:
        try:
            with zipfile.ZipFile(filepath, 'r') as z:
                if 'docProps/core.xml' in z.namelist():
                    xml = z.read('docProps/core.xml').decode('utf-8', errors='ignore')
                    meta = {}
                    for field in ['title','creator','lastModifiedBy','created','modified','description','subject']:
                        m = re.search(f'<{field}>(.*?)</{field}>', xml, re.I|re.S)
                        if m:
                            meta[field] = m.group(1).strip()
                    return meta
        except:
            pass
        return {}

    # ============================================================
    # IP GEOLOCATION
    # ============================================================
    def lookup_ip(self, ip: str) -> Dict:
        try:
            resp = self.session.get(f'http://ip-api.com/json/{ip}', timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except:
            pass
        return {'status': 'fail', 'message': 'Could not geolocate IP'}

    # ============================================================
    # PHONE LOOKUP
    # ============================================================
    def lookup_phone(self, phone: str) -> Dict:
        cleaned = re.sub(r'[^\d+]', '', phone)
        result = {
            'original': phone,
            'cleaned': cleaned,
            'length': len(cleaned.replace('+','')),
            'country_code': cleaned[:3] if cleaned.startswith('+') else 'Unknown',
            'valid_format': bool(re.match(r'^\+?[\d\s-]{7,15}$', phone))
        }
        return result

    # ============================================================
    # REPORT GENERATION
    # ============================================================
    def generate_report(self, results: Dict, report_type: str) -> str:
        REPORTS_DIR.mkdir(exist_ok=True)
        ts = get_timestamp()
        path = REPORTS_DIR / f'raven_{report_type}_{ts}.md'
        with open(path, 'w', encoding='utf-8') as f:
            f.write('# Raven OSINT Report\n\n')
            f.write(f'**Report Type:** {report_type}\n')
            f.write(f'**Generated:** {datetime.now().isoformat()}\n')
            f.write(f'**Tool:** Raven OSINT Framework\n')
            f.write(f'**Organization:** Templar Studios\n\n---\n\n')
            if report_type == 'username':
                f.write(f'## Username Search\n\n**Username:** {results.get("username","N/A")}\n')
                f.write(f'**Found:** {results.get("found_count",0)}/{results.get("total_platforms",0)}\n\n')
                f.write('| Platform | Status | URL |\n|---|---|---|\n')
                for plat, data in results.get('results', {}).items():
                    status = '✅' if data.get('exists') else '❌'
                    f.write(f'| {plat} | {status} | {data.get("url","")} |\n')
            elif report_type == 'email':
                f.write(f'## Email Breach Report\n\n**Email:** {results.get("email","N/A")}\n')
                hibp = results.get('hibp', {})
                if hibp.get('breached'):
                    f.write(f'**Status:** ⚠️ BREACHED — {hibp.get("count",0)} breaches\n')
                else:
                    f.write('**Status:** ✅ No known breaches\n')
                for p in results.get('patterns', []):
                    f.write(f'- {p}\n')
            elif report_type == 'domain':
                f.write(f'## Domain Intelligence\n\n**Domain:** {results.get("domain","N/A")}\n')
                for key in ['ip_addresses','mx_records','txt_records','nameservers','subdomains','technologies']:
                    vals = results.get(key, [])
                    if vals:
                        f.write(f'### {key.replace("_"," ").title()}\n')
                        for v in vals:
                            f.write(f'- {v}\n')
                        f.write('\n')
                if results.get('ssl_info'):
                    f.write('### SSL Certificate\n')
                    for k,v in results['ssl_info'].items():
                        f.write(f'- **{k}:** {v}\n')
            elif report_type == 'ports':
                f.write(f'## Port Scan Report\n\n**Host:** {results.get("host","N/A")}\n')
                f.write(f'**Open Ports:** {len(results.get("open_ports",[]))}\n\n')
                f.write('| Port | Service |\n|---|---|\n')
                for r in results.get('results', []):
                    if r.get('open'):
                        f.write(f'| {r["port"]} | {r["service"]} |\n')
            f.write('\n---\n*Generated by Raven OSINT Framework — Templar Studios*\n')
        return str(path)

    def export_csv(self, results: Dict, report_type: str) -> str:
        REPORTS_DIR.mkdir(exist_ok=True)
        ts = get_timestamp()
        path = REPORTS_DIR / f'raven_{report_type}_{ts}.csv'
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if report_type == 'username':
                writer.writerow(['Platform','Exists','URL'])
                for plat, data in results.get('results', {}).items():
                    writer.writerow([plat, data.get('exists'), data.get('url')])
            elif report_type == 'ports':
                writer.writerow(['Port','Open','Service'])
                for r in results.get('results', []):
                    writer.writerow([r.get('port'), r.get('open'), r.get('service')])
        return str(path)

# ──────────────────────────────────────────────
# GUI
# ──────────────────────────────────────────────
class RavenGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Raven — Advanced OSINT Framework")
        self.root.geometry("1000x750")
        self.root.configure(bg=COLORS['bg'])
        self.engine = RavenEngine()
        self.current_results = {}
        self.setup_ui()
        self.load_config()

    def setup_ui(self):
        # Title bar
        title_frame = tk.Frame(self.root, bg=COLORS['card'], height=70)
        title_frame.pack(fill='x')
        title_frame.pack_propagate(False)
        tk.Label(title_frame, text="Raven", font=('Segoe UI', 28, 'bold'), fg=COLORS['accent'], bg=COLORS['card']).pack(pady=5)
        tk.Label(title_frame, text="ADVANCED OSINT FRAMEWORK — TEMPLAR STUDIOS", font=('Segoe UI', 9, 'bold'), fg=COLORS['dim'], bg=COLORS['card']).pack()

        # Notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Create tabs
        self.create_username_tab()
        self.create_email_tab()
        self.create_domain_tab()
        self.create_ports_tab()
        self.create_metadata_tab()
        self.create_ip_tab()
        self.create_phone_tab()
        self.create_report_tab()

        # Status bar
        status_frame = tk.Frame(self.root, bg=COLORS['card'], height=35)
        status_frame.pack(fill='x', padx=10, pady=(0,5))
        status_frame.pack_propagate(False)
        self.status_label = tk.Label(status_frame, text="Ready", font=('Segoe UI', 10), fg=COLORS['dim'], bg=COLORS['card'])
        self.status_label.pack(side='left', padx=15)
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate', length=150)
        self.progress.pack(side='right', padx=15)

    # Each tab creation methods
    def create_username_tab(self):
        tab = tk.Frame(self.notebook, bg=COLORS['bg'])
        self.notebook.add(tab, text='Username')
        frame = tk.LabelFrame(tab, text="Search Username", bg=COLORS['card'], fg=COLORS['text'], padx=10, pady=10)
        frame.pack(fill='both', expand=True, padx=5, pady=5)
        input_row = tk.Frame(frame, bg=COLORS['card'])
        input_row.pack(fill='x', pady=5)
        self.username_entry = tk.Entry(input_row, bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'], relief='flat', font=('Segoe UI', 11))
        self.username_entry.pack(side='left', fill='x', expand=True, padx=(0,5))
        tk.Button(input_row, text="Search", bg=COLORS['accent'], fg='white', relief='flat', padx=15, pady=5, command=self.run_username_search).pack(side='right')
        self.username_output = scrolledtext.ScrolledText(frame, bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'], relief='flat', font=('Consolas', 9), height=20)
        self.username_output.pack(fill='both', expand=True, pady=5)

    def create_email_tab(self):
        tab = tk.Frame(self.notebook, bg=COLORS['bg'])
        self.notebook.add(tab, text='Email')
        frame = tk.LabelFrame(tab, text="Email Breach Check", bg=COLORS['card'], fg=COLORS['text'], padx=10, pady=10)
        frame.pack(fill='both', expand=True, padx=5, pady=5)
        input_row = tk.Frame(frame, bg=COLORS['card'])
        input_row.pack(fill='x', pady=5)
        self.email_entry = tk.Entry(input_row, bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'], relief='flat', font=('Segoe UI', 11))
        self.email_entry.pack(side='left', fill='x', expand=True, padx=(0,5))
        tk.Button(input_row, text="Check", bg=COLORS['accent'], fg='white', relief='flat', padx=15, pady=5, command=self.run_email_check).pack(side='right')
        self.email_output = scrolledtext.ScrolledText(frame, bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'], relief='flat', font=('Consolas', 9), height=15)
        self.email_output.pack(fill='both', expand=True, pady=5)

    def create_domain_tab(self):
        tab = tk.Frame(self.notebook, bg=COLORS['bg'])
        self.notebook.add(tab, text='Domain')
        frame = tk.LabelFrame(tab, text="Domain Intelligence", bg=COLORS['card'], fg=COLORS['text'], padx=10, pady=10)
        frame.pack(fill='both', expand=True, padx=5, pady=5)
        input_row = tk.Frame(frame, bg=COLORS['card'])
        input_row.pack(fill='x', pady=5)
        self.domain_entry = tk.Entry(input_row, bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'], relief='flat', font=('Segoe UI', 11))
        self.domain_entry.pack(side='left', fill='x', expand=True, padx=(0,5))
        tk.Button(input_row, text="Analyze", bg=COLORS['accent'], fg='white', relief='flat', padx=15, pady=5, command=self.run_domain_lookup).pack(side='right')
        self.domain_output = scrolledtext.ScrolledText(frame, bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'], relief='flat', font=('Consolas', 9), height=20)
        self.domain_output.pack(fill='both', expand=True, pady=5)

    def create_ports_tab(self):
        tab = tk.Frame(self.notebook, bg=COLORS['bg'])
        self.notebook.add(tab, text='Ports')
        frame = tk.LabelFrame(tab, text="Port Scanner", bg=COLORS['card'], fg=COLORS['text'], padx=10, pady=10)
        frame.pack(fill='both', expand=True, padx=5, pady=5)
        input_row = tk.Frame(frame, bg=COLORS['card'])
        input_row.pack(fill='x', pady=5)
        self.port_host_entry = tk.Entry(input_row, bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'], relief='flat', font=('Segoe UI', 11))
        self.port_host_entry.pack(side='left', fill='x', expand=True, padx=(0,5))
        tk.Button(input_row, text="Scan", bg=COLORS['accent'], fg='white', relief='flat', padx=15, pady=5, command=self.run_port_scan).pack(side='right')
        self.port_output = scrolledtext.ScrolledText(frame, bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'], relief='flat', font=('Consolas', 9), height=20)
        self.port_output.pack(fill='both', expand=True, pady=5)

    def create_metadata_tab(self):
        tab = tk.Frame(self.notebook, bg=COLORS['bg'])
        self.notebook.add(tab, text='Metadata')
        frame = tk.LabelFrame(tab, text="Metadata Extractor", bg=COLORS['card'], fg=COLORS['text'], padx=10, pady=10)
        frame.pack(fill='both', expand=True, padx=5, pady=5)
        file_row = tk.Frame(frame, bg=COLORS['card'])
        file_row.pack(fill='x', pady=5)
        self.meta_file_var = tk.StringVar()
        tk.Entry(file_row, textvariable=self.meta_file_var, bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'], relief='flat', font=('Segoe UI', 11)).pack(side='left', fill='x', expand=True, padx=(0,5))
        tk.Button(file_row, text="Browse", bg=COLORS['accent'], fg='white', relief='flat', padx=15, pady=5, command=self.browse_file).pack(side='right')
        tk.Button(frame, text="Extract", bg=COLORS['accent'], fg='white', relief='flat', padx=15, pady=5, command=self.run_metadata).pack(pady=5)
        self.metadata_output = scrolledtext.ScrolledText(frame, bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'], relief='flat', font=('Consolas', 9), height=20)
        self.metadata_output.pack(fill='both', expand=True, pady=5)

    def create_ip_tab(self):
        tab = tk.Frame(self.notebook, bg=COLORS['bg'])
        self.notebook.add(tab, text='IP Lookup')
        frame = tk.LabelFrame(tab, text="IP Geolocation", bg=COLORS['card'], fg=COLORS['text'], padx=10, pady=10)
        frame.pack(fill='both', expand=True, padx=5, pady=5)
        input_row = tk.Frame(frame, bg=COLORS['card'])
        input_row.pack(fill='x', pady=5)
        self.ip_entry = tk.Entry(input_row, bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'], relief='flat', font=('Segoe UI', 11))
        self.ip_entry.pack(side='left', fill='x', expand=True, padx=(0,5))
        tk.Button(input_row, text="Lookup", bg=COLORS['accent'], fg='white', relief='flat', padx=15, pady=5, command=self.run_ip_lookup).pack(side='right')
        self.ip_output = scrolledtext.ScrolledText(frame, bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'], relief='flat', font=('Consolas', 9), height=15)
        self.ip_output.pack(fill='both', expand=True, pady=5)

    def create_phone_tab(self):
        tab = tk.Frame(self.notebook, bg=COLORS['bg'])
        self.notebook.add(tab, text='Phone')
        frame = tk.LabelFrame(tab, text="Phone Lookup", bg=COLORS['card'], fg=COLORS['text'], padx=10, pady=10)
        frame.pack(fill='both', expand=True, padx=5, pady=5)
        input_row = tk.Frame(frame, bg=COLORS['card'])
        input_row.pack(fill='x', pady=5)
        self.phone_entry = tk.Entry(input_row, bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'], relief='flat', font=('Segoe UI', 11))
        self.phone_entry.pack(side='left', fill='x', expand=True, padx=(0,5))
        tk.Button(input_row, text="Analyze", bg=COLORS['accent'], fg='white', relief='flat', padx=15, pady=5, command=self.run_phone_lookup).pack(side='right')
        self.phone_output = scrolledtext.ScrolledText(frame, bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'], relief='flat', font=('Consolas', 9), height=10)
        self.phone_output.pack(fill='both', expand=True, pady=5)

    def create_report_tab(self):
        tab = tk.Frame(self.notebook, bg=COLORS['bg'])
        self.notebook.add(tab, text='Report')
        frame = tk.LabelFrame(tab, text="Generate Report", bg=COLORS['card'], fg=COLORS['text'], padx=10, pady=10)
        frame.pack(fill='both', expand=True, padx=5, pady=5)
        tk.Label(frame, text="Select report type from previous results:", bg=COLORS['card'], fg=COLORS['dim']).pack(anchor='w')
        self.report_type_var = tk.StringVar(value='username')
        for rtype in ['username','email','domain','ports']:
            tk.Radiobutton(frame, text=rtype.capitalize(), variable=self.report_type_var, value=rtype, bg=COLORS['card'], fg=COLORS['text'], selectcolor=COLORS['bg'], activebackground=COLORS['card']).pack(anchor='w')
        tk.Button(frame, text="Generate Markdown Report", bg=COLORS['accent'], fg='white', relief='flat', padx=15, pady=5, command=self.generate_report).pack(pady=5)
        self.report_output = scrolledtext.ScrolledText(frame, bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'], relief='flat', font=('Consolas', 9), height=10)
        self.report_output.pack(fill='both', expand=True, pady=5)

    # Action methods
    def run_username_search(self):
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Error", "Enter a username")
            return
        self.username_output.delete('1.0', tk.END)
        self.username_output.insert(tk.END, f"Searching for '{username}' across 50+ platforms...\n")
        self.status_label.config(text="Searching...")
        self.progress.start()
        threading.Thread(target=self._username_thread, args=(username,), daemon=True).start()

    def _username_thread(self, username):
        def callback(platform, result, completed, total, found):
            self.root.after(0, lambda: self._update_username_output(platform, result, completed, total, found))
        self.engine.running = True
        results = self.engine.search_username(username, callback)
        self.engine.running = False
        self.current_results['username'] = results
        self.root.after(0, self.progress.stop)
        self.root.after(0, lambda: self.status_label.config(text="Search complete"))
        self.root.after(0, lambda: self._final_username(results))

    def _update_username_output(self, platform, result, completed, total, found):
        status = "FOUND" if result.get('exists') else "not found"
        self.username_output.insert(tk.END, f"{platform:25} {status}  ({completed}/{total})\n")
        self.username_output.see(tk.END)

    def _final_username(self, results):
        self.username_output.insert(tk.END, f"\nDone. Found on {results['found_count']}/{results['total_platforms']} platforms.\n")

    # Similar thread methods for other actions
    def run_email_check(self):
        email = self.email_entry.get().strip()
        if not email:
            messagebox.showerror("Error", "Enter email")
            return
        self.email_output.delete('1.0', tk.END)
        self.status_label.config(text="Checking...")
        threading.Thread(target=self._email_thread, args=(email,), daemon=True).start()

    def _email_thread(self, email):
        result = self.engine.check_email_breach(email)
        self.current_results['email'] = result
        self.root.after(0, lambda: self._display_email(result))

    def _display_email(self, result):
        self.email_output.delete('1.0', tk.END)
        if not result.get('valid'):
            self.email_output.insert(tk.END, f"Error: {result.get('error')}\n")
            return
        hibp = result.get('hibp', {})
        if hibp.get('breached'):
            self.email_output.insert(tk.END, f"⚠️ BREACHED — {hibp.get('count',0)} breaches (source: {hibp.get('source','')})\n")
        else:
            self.email_output.insert(tk.END, f"✅ No breaches found\n")
        for p in result.get('patterns', []):
            self.email_output.insert(tk.END, f"  - {p}\n")
        self.status_label.config(text="Email check complete")

    def run_domain_lookup(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Enter domain")
            return
        self.domain_output.delete('1.0', tk.END)
        self.status_label.config(text="Analyzing domain...")
        threading.Thread(target=self._domain_thread, args=(domain,), daemon=True).start()

    def _domain_thread(self, domain):
        result = self.engine.get_domain_info(domain)
        self.current_results['domain'] = result
        self.root.after(0, lambda: self._display_domain(result))

    def _display_domain(self, result):
        self.domain_output.delete('1.0', tk.END)
        for key in ['domain','ip_addresses','mx_records','txt_records','nameservers','subdomains','technologies']:
            if key == 'domain':
                self.domain_output.insert(tk.END, f"Domain: {result['domain']}\n\n")
            else:
                vals = result.get(key, [])
                if vals:
                    self.domain_output.insert(tk.END, f"{key.replace('_',' ').title()}:\n")
                    for v in vals:
                        self.domain_output.insert(tk.END, f"  {v}\n")
                    self.domain_output.insert(tk.END, "\n")
        if result.get('ssl_info'):
            self.domain_output.insert(tk.END, "SSL Certificate:\n")
            for k,v in result['ssl_info'].items():
                self.domain_output.insert(tk.END, f"  {k}: {v}\n")
        self.status_label.config(text="Domain analysis complete")

    def run_port_scan(self):
        host = self.port_host_entry.get().strip()
        if not host:
            messagebox.showerror("Error", "Enter host")
            return
        self.port_output.delete('1.0', tk.END)
        self.status_label.config(text="Scanning ports...")
        self.progress.start()
        threading.Thread(target=self._port_thread, args=(host,), daemon=True).start()

    def _port_thread(self, host):
        def callback(port, is_open, completed, total):
            if is_open:
                self.root.after(0, lambda: self.port_output.insert(tk.END, f"Port {port}: OPEN\n"))
        results = self.engine.scan_ports(host, callback=callback)
        self.current_results['ports'] = results
        self.root.after(0, self.progress.stop)
        self.root.after(0, lambda: self._display_ports(results))

    def _display_ports(self, results):
        self.port_output.insert(tk.END, f"\nScan complete. Open ports: {results['open_ports']}\n")
        self.status_label.config(text="Port scan complete")

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.meta_file_var.set(filename)

    def run_metadata(self):
        filepath = self.meta_file_var.get().strip()
        if not filepath or not os.path.exists(filepath):
            messagebox.showerror("Error", "Select a valid file")
            return
        self.metadata_output.delete('1.0', tk.END)
        self.status_label.config(text="Extracting metadata...")
        threading.Thread(target=self._metadata_thread, args=(filepath,), daemon=True).start()

    def _metadata_thread(self, filepath):
        result = self.engine.extract_metadata(filepath)
        self.root.after(0, lambda: self._display_metadata(result))

    def _display_metadata(self, meta):
        self.metadata_output.delete('1.0', tk.END)
        for key, value in meta.items():
            if isinstance(value, dict):
                self.metadata_output.insert(tk.END, f"{key}:\n")
                for k,v in value.items():
                    self.metadata_output.insert(tk.END, f"  {k}: {v}\n")
            elif isinstance(value, list):
                self.metadata_output.insert(tk.END, f"{key}:\n")
                for item in value[:20]:
                    self.metadata_output.insert(tk.END, f"  {item}\n")
            else:
                self.metadata_output.insert(tk.END, f"{key}: {value}\n")
        self.status_label.config(text="Metadata extraction complete")

    def run_ip_lookup(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Enter IP")
            return
        self.ip_output.delete('1.0', tk.END)
        self.status_label.config(text="Looking up IP...")
        threading.Thread(target=self._ip_thread, args=(ip,), daemon=True).start()

    def _ip_thread(self, ip):
        result = self.engine.lookup_ip(ip)
        self.root.after(0, lambda: self._display_ip(result))

    def _display_ip(self, result):
        self.ip_output.delete('1.0', tk.END)
        if result.get('status') == 'success':
            for k,v in result.items():
                self.ip_output.insert(tk.END, f"{k}: {v}\n")
        else:
            self.ip_output.insert(tk.END, "Failed to geolocate IP\n")
        self.status_label.config(text="IP lookup complete")

    def run_phone_lookup(self):
        phone = self.phone_entry.get().strip()
        if not phone:
            messagebox.showerror("Error", "Enter phone number")
            return
        result = self.engine.lookup_phone(phone)
        self.phone_output.delete('1.0', tk.END)
        for k,v in result.items():
            self.phone_output.insert(tk.END, f"{k}: {v}\n")
        self.status_label.config(text="Phone analysis complete")

    def generate_report(self):
        rtype = self.report_type_var.get()
        if rtype not in self.current_results:
            messagebox.showerror("Error", f"No {rtype} results available. Run that search first.")
            return
        path = self.engine.generate_report(self.current_results[rtype], rtype)
        self.report_output.delete('1.0', tk.END)
        self.report_output.insert(tk.END, f"Report generated: {path}\n")
        self.status_label.config(text="Report generated")

    def load_config(self):
        if CONFIG_PATH.exists():
            try:
                with open(CONFIG_PATH, 'r') as f:
                    cfg = json.load(f)
                    if 'username' in cfg: self.username_entry.insert(0, cfg['username'])
                    if 'email' in cfg: self.email_entry.insert(0, cfg['email'])
            except: pass

    def run(self):
        self.root.mainloop()

# ──────────────────────────────────────────────
# CLI MODE
# ──────────────────────────────────────────────
def run_cli():
    print("Raven OSINT Framework — CLI Mode")
    print("Available modules: username, email, domain, ports, metadata, ip, phone")
    while True:
        cmd = input("\nraven> ").strip().lower()
        if cmd in ('exit','quit'):
            break
        engine = RavenEngine()
        if cmd == 'username':
            u = input("Username: ")
            res = engine.search_username(u)
            print(f"\nFound {res['found_count']} profiles:")
            for plat, data in res['results'].items():
                if data.get('exists'):
                    print(f"  [+] {plat}: {data['url']}")
        elif cmd == 'email':
            e = input("Email: ")
            res = engine.check_email_breach(e)
            hibp = res.get('hibp', {})
            if hibp.get('breached'):
                print(f"⚠️ BREACHED — {hibp['count']} breaches")
            else:
                print("✅ No known breaches")
        elif cmd == 'domain':
            d = input("Domain: ")
            res = engine.get_domain_info(d)
            print(json.dumps(res, indent=2, default=str))
        elif cmd == 'ports':
            h = input("Host: ")
            res = engine.scan_ports(h)
            print(f"Open ports: {res['open_ports']}")
        elif cmd == 'metadata':
            f = input("File path: ")
            res = engine.extract_metadata(f)
            print(json.dumps(res, indent=2, default=str))
        elif cmd == 'ip':
            ip = input("IP: ")
            print(json.dumps(engine.lookup_ip(ip), indent=2))
        elif cmd == 'phone':
            p = input("Phone: ")
            print(json.dumps(engine.lookup_phone(p), indent=2))
        else:
            print("Unknown command")

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
if __name__ == "__main__":
    if '--cli' in sys.argv:
        run_cli()
    else:
        gui = RavenGUI()
        gui.run()