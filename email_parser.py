import email
from email.policy import default
import re
from bs4 import BeautifulSoup

def parse_email_content(raw_bytes_or_str):
    """
    Parses raw email (bytes or string) into extracted headers, authentication results, and clean body text.
    Returns: (headers: dict, body_text: str)
    """
    if isinstance(raw_bytes_or_str, str):
        msg = email.message_from_string(raw_bytes_or_str, policy=default)
    else:
        msg = email.message_from_bytes(raw_bytes_or_str, policy=default)

    headers = {}
    for key in ['From', 'To', 'Subject', 'Date', 'Message-ID', 'Return-Path']:
        headers[key] = str(msg.get(key, '')).strip()

    # Extract Received headers and IPs
    received_list = msg.get_all('Received', [])
    headers['Received'] = [str(r).strip() for r in received_list]
    
    # Extract IPv4 hops from Received chain
    combined_received = '\n'.join(headers['Received'])
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', combined_received)
    # Filter out common localhost / loopback IPs
    filtered_ips = [ip for ip in ips if not ip.startswith('127.') and ip != '0.0.0.0']
    headers['received_ips'] = list(dict.fromkeys(filtered_ips)) # preserve order, remove duplicates

    # Check SPF and DKIM authentication results
    auth_results = str(msg.get('Authentication-Results', '')) + " " + str(msg.get('Received-SPF', ''))
    auth_lower = auth_results.lower()

    if 'spf=pass' in auth_lower or 'received-spf: pass' in auth_lower:
        headers['spf'] = 'pass'
    elif 'spf=fail' in auth_lower or 'spf=softfail' in auth_lower or 'received-spf: fail' in auth_lower or 'received-spf: softfail' in auth_lower:
        headers['spf'] = 'fail'
    else:
        headers['spf'] = 'unknown'

    if 'dkim=pass' in auth_lower:
        headers['dkim'] = 'pass'
    elif 'dkim=fail' in auth_lower:
        headers['dkim'] = 'fail'
    else:
        headers['dkim'] = 'unknown'

    # Extract Body
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition', ''))
            
            # Skip attachments
            if 'attachment' in content_disposition:
                continue

            try:
                if content_type == 'text/plain':
                    body_text += part.get_content() + "\n"
                elif content_type == 'text/html' and not body_text:
                    html_content = part.get_content()
                    soup = BeautifulSoup(html_content, 'html.parser')
                    body_text = soup.get_text(separator=' ')
            except Exception:
                continue
    else:
        try:
            content = msg.get_content()
            if msg.get_content_type() == 'text/html':
                soup = BeautifulSoup(content, 'html.parser')
                body_text = soup.get_text(separator=' ')
            else:
                body_text = str(content)
        except Exception:
            body_text = str(msg.get_payload())

    # Clean excessive whitespace
    body_text = re.sub(r'\s+', ' ', body_text).strip()
    return headers, body_text

def parse_email_file(filepath):
    """Convenience method to parse an email from a file path."""
    with open(filepath, 'rb') as f:
        return parse_email_content(f.read())
