import requests
import re
import base64
import json

def extract_csrf_from_session(session_cookie: str) -> str:
    try:
        import base64
        parts = session_cookie.split('N', 1)
        if len(parts) > 1:
            candidate = 'N' + parts[1]
            padding = 4 - len(candidate) % 4
            if padding != 4:
                candidate += '=' * padding
            try:
                decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
                csrf_match = re.search(r'"_csrft_":\s*"([a-f0-9]+)"', decoded)
                if csrf_match:
                    return csrf_match.group(1)
            except Exception:
                pass
        hex_matches = re.findall(r'[a-f0-9]{40}', session_cookie)
        if hex_matches:
            return hex_matches[0]
        return None
    except Exception as e:
        print(f"Error extracting CSRF: {e}")
        return None

def get_all_tokens(email: str, password: str, aws_waf_token: str):
    """
    Given your aws-waf-token (copied from browser), 
    performs login and returns all tokens needed.
    """
    session = requests.Session()
    
    base_headers = {
        "accept-language": "en-US,en;q=0.9",
        "dnt": "1",
        "sec-ch-ua": '"Chromium";v="148", "Brave";v="148", "Not/A)Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-gpc": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
    }
    
    session.cookies.set("aws-waf-token", aws_waf_token, domain="app.dimensions.ai")
    
    print("Step 1: Getting landing page...")
    landing = session.get(
        "https://app.dimensions.ai/auth/base/landing?redirect=%2Fdiscover",
        headers={**base_headers, "accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
        timeout=30
    )
    print(f"  Landing status: {landing.status_code}")
    
    initial_session = session.cookies.get("session")
    if not initial_session:
        print("ERROR: No session cookie from landing page")
        return None
    
    print("Step 2: Extracting CSRF token...")
    csrf_token = extract_csrf_from_session(initial_session)
    if not csrf_token:
        print("ERROR: Could not extract CSRF token")
        return None
    print(f"  CSRF: {csrf_token[:8]}...")
    
    print("Step 3: Logging in...")
    login = session.post(
        "https://app.dimensions.ai/auth/dimensions/login/auth.json?redirect=%2Fdiscover",
        headers={
            **base_headers,
            "accept": "application/json",
            "content-type": "application/json",
            "origin": "https://app.dimensions.ai",
            "referer": "https://app.dimensions.ai/auth/base/landing?redirect=%2Fdiscover",
            "x-csrf-token": csrf_token,
            "x-requested-with": "XMLHttpRequest",
        },
        json={"agreement_signed": False, "password": password, "username": email},
        timeout=30
    )
    print(f"  Login status: {login.status_code}")
    
    if login.status_code != 200:
        print(f"ERROR: Login failed: {login.text[:200]}")
        return None

    auth_session = session.cookies.get("session")
    auth_ticket = session.cookies.get("uber_auth_tkt")
    fresh_csrf = extract_csrf_from_session(auth_session) if auth_session else csrf_token

    if not auth_ticket:
        print("ERROR: No uber_auth_tkt after login - login may have failed")
        print(f"Response: {login.text[:200]}")
        return None

    print("\n✅ SUCCESS - Copy these values into GitHub Actions inputs:\n")
    print(f"  AWS_WAF_TOKEN : {aws_waf_token}")
    print(f"  SESSION       : {auth_session}")
    print(f"  AUTH_TICKET   : {auth_ticket}")
    print(f"  CSRF_TOKEN    : {fresh_csrf}")
    
    return {
        "aws_waf_token": aws_waf_token,
        "session": auth_session,
        "uber_auth_tkt": auth_ticket,
        "csrf_token": fresh_csrf,
    }

if __name__ == "__main__":
    # Paste your current aws-waf-token from browser DevTools > Application > Cookies
    AWS_WAF_TOKEN = "paste-your-aws-waf-token-here"
    EMAIL = "your@email.edu"
    PASSWORD = "yourpassword"
    
    tokens = get_all_tokens(EMAIL, PASSWORD, AWS_WAF_TOKEN)
