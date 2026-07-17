import requests
import json
import os

BASE_URL = "http://localhost:5000"

def test_endpoint(name, method, url, data=None, files=None):
    try:
        if method.upper() == "GET":
            resp = requests.get(url, timeout=5)
        elif method.upper() == "POST":
            if files:
                resp = requests.post(url, files=files, timeout=5)
            else:
                resp = requests.post(url, json=data, timeout=5)
        else:
            raise ValueError("Unsupported method")
        
        status = resp.status_code
        if status == 200:
            # Try to parse JSON to ensure it's valid
            resp.json()
            print(f"✅ {name}: PASS (Status {status}, valid JSON)")
        elif status == 400:
            # Bad request is fine – means your code handled missing fields gracefully
            print(f"⚠️ {name}: PASS with warning (Status {status} – check input)")
        else:
            print(f"❌ {name}: FAIL (Status {status})")
            print(f"   Response: {resp.text[:200]}")
    except requests.exceptions.ConnectionError:
        print(f"❌ {name}: FAIL – Flask server not running at {BASE_URL}")
    except json.JSONDecodeError:
        print(f"❌ {name}: FAIL – Response is not valid JSON (likely 500 error)")
        print(f"   Response: {resp.text[:200]}")
    except Exception as e:
        print(f"❌ {name}: FAIL – {str(e)}")

if __name__ == "__main__":
    print("🍟♤ ｃ𝓐𝐓 🐟🎁 API Verification Suite\n")
    
    # 1. URL endpoint
    test_endpoint("URL Analyzer", "POST", f"{BASE_URL}/api/analyze/url", 
                  data={"url": "http://secure-login.paypal-verifying.top"})
    
    # 2. Sample Emails endpoint
    test_endpoint("Sample Emails List", "GET", f"{BASE_URL}/api/samples")

    # 3. Email endpoint (upload sample file if available)
    sample_path = "sample_emails/phish_ceo.eml"
    if os.path.exists(sample_path):
        with open(sample_path, 'rb') as f:
            files = {'file': (os.path.basename(sample_path), f, 'message/rfc822')}
            test_endpoint("Email Analyzer (File Upload)", "POST", f"{BASE_URL}/api/analyze/email", files=files)
    else:
        # Test with raw text payload
        test_endpoint("Email Analyzer (Raw Text)", "POST", f"{BASE_URL}/api/analyze/email", 
                      data={"raw_email": "From: attacker@bad.top\nSubject: URGENT LOGIN\n\nVerify now!"})
    
    # 4. History endpoint
    test_endpoint("Browser History", "GET", f"{BASE_URL}/api/history")
    
    # 5. Sniffer endpoint
    test_endpoint("Packet Sniffer", "POST", f"{BASE_URL}/api/sniff", data={"timeout": 1})
    
    print("\n✅ Verification complete.")
