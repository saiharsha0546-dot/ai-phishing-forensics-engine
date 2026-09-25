import os
import requests
import hashlib
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
