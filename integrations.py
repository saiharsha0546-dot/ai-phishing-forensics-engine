import os
import requests
import hashlib
import imaplib
import email
from email.header import decode_header
import base64

def check_virustotal(url):
    """
    Queries VirusTotal API for URL analysis.
    If no VT_API_KEY is found, returns a safe mock response to keep the UI functional.
    """
    vt_key = os.environ.get('VT_API_KEY', 'b5062e2371c45aba37b5f5398833f0a3f26f3c3cc241cc105d0871a903e7ecca')
    if not vt_key:
        return {
            'status': 'mocked',
            'positives': 0,
            'total': 90,
            'message': 'VirusTotal API Key missing. Mocked safe result.'
        }
    
    # VirusTotal API v3 uses a base64 encoded URL identifier without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {
        "accept": "application/json",
        "x-apikey": vt_key
    }
    try:
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
        if res.status_code == 200:
            data = res.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            return {
                'status': 'success',
                'positives': malicious + suspicious,
                'total': total,
                'message': f"Flagged by {malicious+suspicious} out of {total} security vendors."
            }
        elif res.status_code == 404:
            return {'status': 'unscanned', 'positives': 0, 'total': 0, 'message': 'URL not yet scanned by VirusTotal.'}
        else:
            return {'status': 'error', 'positives': 0, 'total': 0, 'message': f'VT API Error: {res.status_code}'}
    except Exception as e:
        return {'status': 'error', 'positives': 0, 'total': 0, 'message': f'Connection failed: {str(e)}'}

def check_pwned_password(password):
    """
    Securely checks HaveIBeenPwned using k-Anonymity.
    Only the first 5 characters of the SHA-1 hash are sent over the network.
    """
    if not password:
        return {'found': False, 'count': 0}
        
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    
    try:
        res = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=5)
        if res.status_code != 200:
            return {'error': 'Failed to reach HIBP API.'}
            
        hashes = (line.split(':') for line in res.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return {'found': True, 'count': int(count)}
        return {'found': False, 'count': 0}
    except Exception as e:
        return {'error': str(e)}

def _decode_str(s):
    if not s: return ""
    decoded_parts = decode_header(s)
    result = ""
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            try:
                result += part.decode(encoding or 'utf-8', errors='ignore')
            except LookupError:
                result += part.decode('utf-8', errors='ignore')
        else:
            result += part
    return result

def scan_imap_inbox(email_addr, password, server_host='imap.gmail.com', port=993, limit=5):
    """
    Connects to IMAP server securely, fetches the last `limit` emails,
    and returns their raw text and metadata to be processed by the AI model.
    """
    try:
        mail = imaplib.IMAP4_SSL(server_host, int(port))
        mail.login(email_addr, password)
        mail.select("inbox")
        
        status, messages = mail.search(None, 'ALL')
        if status != 'OK':
            return {'error': 'Failed to search inbox.'}
            
        email_ids = messages[0].split()
        latest_ids = email_ids[-limit:]
        
        fetched_emails = []
        for e_id in reversed(latest_ids):
            res, msg_data = mail.fetch(e_id, '(RFC822)')
            if res == 'OK':
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        raw_email = response_part[1]
                        try:
                            decoded = raw_email.decode('utf-8', errors='ignore')
                            fetched_emails.append(decoded)
                        except Exception:
                            fetched_emails.append(raw_email.decode('latin1', errors='ignore'))
                            
        mail.logout()
        return {'status': 'success', 'emails': fetched_emails}
    except imaplib.IMAP4.error as e:
        return {'error': f'Authentication Failed. (Did you use an App Password?): {str(e)}'}
    except Exception as e:
        return {'error': f'IMAP Error: {str(e)}'}
