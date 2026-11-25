"""
Universal Headless & Cloud Screenshot Capture Engine.
1. Primary: Uses local Headless Chrome/Edge/Chromium if available (Desktop / Docker).
2. Cloud Fallback: Uses high-speed, free headless rendering services (thum.io / microlink)
   so screenshots and Siamese visual comparison work seamlessly on Render's free tier
   without requiring Chromium binaries or paid Docker tiers!
"""
import os
import subprocess
import hashlib
import time
import urllib.request
from urllib.parse import urlparse, quote

CHROME_PATHS = [
    # Windows
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    # Linux native
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser"
]

def find_browser_executable() -> str:
    env_bin = os.environ.get("CHROME_BIN") or os.environ.get("CHROME_PATH")
    if env_bin and os.path.exists(env_bin):
        return env_bin

    for path in CHROME_PATHS:
        if os.path.exists(path):
            return path

    import shutil
    for cmd in ["google-chrome", "chromium", "chromium-browser", "chrome"]:
        w = shutil.which(cmd)
        if w:
            return w

    return None

def capture_cloud_screenshot(target_url: str, output_path: str, timeout: int = 10) -> bool:
    """
    Cloud fallback when native Chrome is not installed (e.g. on Render standard free tier).
    Fetches rendered desktop viewport snapshot (1280x800) via high-speed web screenshot endpoints.
    """
    providers = [
        f"https://image.thum.io/get/width/1280/crop/800/{target_url}",
        f"https://api.microlink.io/?url={quote(target_url)}&screenshot=true&meta=false&embed=screenshot.url"
    ]

    for endpoint in providers:
        try:
            req = urllib.request.Request(
                endpoint,
                headers={"User-Agent": "PhishGuard-Cloud-Sentinel/2.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    data = response.read()
                    if len(data) > 1500:
                        with open(output_path, "wb") as f:
                            f.write(data)
                        return True
        except Exception:
            continue
    return False

def capture_screenshot(target_url: str, output_dir: str = "frontend/screenshots", timeout: int = 10) -> dict:
    """
    Renders target_url and stores screenshot.
    Automatically handles local headless browser OR cloud fallback.
    """
    os.makedirs(output_dir, exist_ok=True)
    
    url_hash = hashlib.md5(target_url.encode()).hexdigest()[:12]
    filename = f"capture_{url_hash}.png"
    abs_output_path = os.path.abspath(os.path.join(output_dir, filename))
    relative_url = f"/screenshots/{filename}"

    # Try 1: Local headless browser (if Chrome/Edge is installed on system)
    browser_exe = find_browser_executable()
    if browser_exe:
        args = [
            browser_exe,
            "--headless=new",
            "--disable-gpu",
            "--hide-scrollbars",
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--window-size=1280,800",
            f"--screenshot={abs_output_path}",
            target_url
        ]
        try:
            subprocess.run(args, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if os.path.exists(abs_output_path) and os.path.getsize(abs_output_path) > 1000:
                return {
                    "success": True,
                    "screenshot_path": abs_output_path,
                    "relative_url": relative_url,
                    "file_size": os.path.getsize(abs_output_path),
                    "source": "Local Headless Chromium",
                    "error": None
                }
        except Exception:
            pass

    # Try 2: Cloud Fallback Rendering (Guaranteed to work on Render Free without Chromium installed!)
    cloud_success = capture_cloud_screenshot(target_url, abs_output_path, timeout=timeout)
    if cloud_success and os.path.exists(abs_output_path) and os.path.getsize(abs_output_path) > 1000:
        return {
            "success": True,
            "screenshot_path": abs_output_path,
            "relative_url": relative_url,
            "file_size": os.path.getsize(abs_output_path),
            "source": "Cloud Headless Renderer",
            "error": None
        }

    return {
        "success": False,
        "error": "Unable to render screenshot via native browser or cloud fallback.",
        "screenshot_path": None,
        "relative_url": None
    }
