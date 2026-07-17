import sqlite3
import os
import shutil
import tempfile
import glob
from datetime import datetime, timedelta

def get_browser_history(browser="all", limit=100):
    """
    Safely retrieves visited URLs from local Chrome, Edge, or Firefox profiles on Windows/Linux.
    Copies the SQLite database to a temp file before reading to prevent 'database is locked' errors.
    If no history or profiles are found, returns realistic forensic mock records for testing/demonstration.
    """
    results = []
    
    if browser in ("all", "chrome"):
        results.extend(_get_chromium_history("chrome", limit // 2))
    if browser in ("all", "edge"):
        results.extend(_get_chromium_history("edge", limit // 2))
    if browser in ("all", "firefox"):
        results.extend(_get_firefox_history(limit // 2))

    # Sort combined results by time descending
    results.sort(key=lambda x: x['time'], reverse=True)

    # If no local history found (e.g. clean virtual machine or locked down permissions),
    # provide rich simulated forensic browsing data for the SOC dashboard demonstration.
    if not results:
        results = _get_mock_history()

    return results[:limit]

def _get_chromium_history(browser_type, limit=50):
    """Extracts history from Chromium-based browsers (Chrome, Edge)."""
    paths_to_check = []
    if os.name == 'nt':  # Windows
        local_app_data = os.environ.get('LOCALAPPDATA', os.path.expanduser('~\\AppData\\Local'))
        if browser_type == 'chrome':
            paths_to_check.append(os.path.join(local_app_data, 'Google', 'Chrome', 'User Data', 'Default', 'History'))
            paths_to_check.append(os.path.join(local_app_data, 'Google', 'Chrome', 'User Data', 'Profile 1', 'History'))
        elif browser_type == 'edge':
            paths_to_check.append(os.path.join(local_app_data, 'Microsoft', 'Edge', 'User Data', 'Default', 'History'))
    else:  # Linux / macOS
        if browser_type == 'chrome':
            paths_to_check.append(os.path.expanduser('~/.config/google-chrome/Default/History'))
            paths_to_check.append(os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/History'))
        elif browser_type == 'edge':
            paths_to_check.append(os.path.expanduser('~/.config/microsoft-edge/Default/History'))

    for db_path in paths_to_check:
        if os.path.exists(db_path):
            temp_db = os.path.join(tempfile.gettempdir(), f"temp_{browser_type}_history_{os.getpid()}.sqlite")
            try:
                # Copy file safely to avoid database lock error
                shutil.copy2(db_path, temp_db)
                conn = sqlite3.connect(temp_db)
                c = conn.cursor()
                c.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT ?", (limit,))
                rows = c.fetchall()
                conn.close()

                # Convert Chromium time (microseconds since 1601-01-01 UTC)
                chrome_epoch = datetime(1601, 1, 1)
                results = []
                for url, title, ts in rows:
                    if url and not url.startswith('chrome://') and not url.startswith('edge://'):
                        try:
                            visit_dt = chrome_epoch + timedelta(microseconds=int(ts))
                            time_str = visit_dt.strftime('%Y-%m-%d %H:%M:%S')
                        except Exception:
                            time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        results.append({
                            'url': url,
                            'title': title or 'No Title',
                            'time': time_str,
                            'source': browser_type.capitalize()
                        })
                return results
            except Exception as e:
                # Silently skip if copy or query failed (e.g. permission issues)
                pass
            finally:
                if os.path.exists(temp_db):
                    try:
                        os.remove(temp_db)
                    except Exception:
                        pass
    return []

def _get_firefox_history(limit=50):
    """Extracts history from Mozilla Firefox places.sqlite."""
    paths_to_check = []
    if os.name == 'nt':
        app_data = os.environ.get('APPDATA', os.path.expanduser('~\\AppData\\Roaming'))
        profile_glob = os.path.join(app_data, 'Mozilla', 'Firefox', 'Profiles', '*', 'places.sqlite')
        paths_to_check.extend(glob.glob(profile_glob))
    else:
        profile_glob = os.path.expanduser('~/.mozilla/firefox/*/places.sqlite')
        paths_to_check.extend(glob.glob(profile_glob))

    for db_path in paths_to_check:
        if os.path.exists(db_path):
            temp_db = os.path.join(tempfile.gettempdir(), f"temp_firefox_places_{os.getpid()}.sqlite")
            try:
                shutil.copy2(db_path, temp_db)
                conn = sqlite3.connect(temp_db)
                c = conn.cursor()
                # Firefox uses moz_places and moz_historyvisits (timestamp in microseconds since epoch)
                c.execute("""
                    SELECT moz_places.url, moz_places.title, moz_historyvisits.visit_date
                    FROM moz_places
                    JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
                    ORDER BY moz_historyvisits.visit_date DESC LIMIT ?
                """, (limit,))
                rows = c.fetchall()
                conn.close()

                results = []
                for url, title, ts in rows:
                    if url and not url.startswith('about:'):
                        try:
                            visit_dt = datetime.fromtimestamp(int(ts) / 1000000.0)
                            time_str = visit_dt.strftime('%Y-%m-%d %H:%M:%S')
                        except Exception:
                            time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        results.append({
                            'url': url,
                            'title': title or 'No Title',
                            'time': time_str,
                            'source': 'Firefox'
                        })
                return results
            except Exception:
                pass
            finally:
                if os.path.exists(temp_db):
                    try:
                        os.remove(temp_db)
                    except Exception:
                        pass
    return []

def _get_mock_history():
    """Returns realistic forensic sample history when running in restricted environments."""
    now = datetime.now()
    return [
        {
            'url': 'http://secure-update-paypal-verify.login-bank.ru/signin.php?session=849302',
            'title': 'PayPal - Confirm Your Account Credentials',
            'time': (now - timedelta(minutes=12)).strftime('%Y-%m-%d %H:%M:%S'),
            'source': 'Chrome (SOC Simulation)'
        },
        {
            'url': 'https://github.com/login',
            'title': 'Sign in to GitHub · GitHub',
            'time': (now - timedelta(minutes=45)).strftime('%Y-%m-%d %H:%M:%S'),
            'source': 'Chrome (SOC Simulation)'
        },
        {
            'url': 'http://185.220.101.42/payload/invoice_8492.scr',
            'title': 'Download Invoice #8492',
            'time': (now - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'),
            'source': 'Edge (SOC Simulation)'
        },
        {
            'url': 'https://www.google.com/search?q=how+to+detect+phishing+email+headers',
            'title': 'how to detect phishing email headers - Google Search',
            'time': (now - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S'),
            'source': 'Chrome (SOC Simulation)'
        },
        {
            'url': 'http://apple-id-locked-verify-billing.top/account/verify.html',
            'title': 'Apple ID - Account Locked Security Warning',
            'time': (now - timedelta(hours=3)).strftime('%Y-%m-%d %H:%M:%S'),
            'source': 'Firefox (SOC Simulation)'
        },
        {
            'url': 'https://stackoverflow.com/questions/4211209/sqlite3-operationalerror-database-is-locked',
            'title': 'python - sqlite3.OperationalError: database is locked - Stack Overflow',
            'time': (now - timedelta(hours=5)).strftime('%Y-%m-%d %H:%M:%S'),
            'source': 'Chrome (SOC Simulation)'
        },
        {
            'url': 'http://signin.chase.com.security-alert-department.work/login.aspx',
            'title': 'Chase Online Bank Verification',
            'time': (now - timedelta(hours=6)).strftime('%Y-%m-%d %H:%M:%S'),
            'source': 'Edge (SOC Simulation)'
        }
    ]
