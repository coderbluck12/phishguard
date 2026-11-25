"""
Headless Browser Screenshot Capture Engine.
Spawns an isolated headless Chromium process to render target webpages,
capture high-resolution viewports, and store them for visual analysis.
"""
import os
import subprocess
import hashlib
import time
from urllib.parse import urlparse

CHROME_PATHS = [
    # Windows paths
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    # Linux / Cloud Container paths (Render, Railway, Hugging Face, Debian/Ubuntu)
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/msedge"
]

def find_browser_executable() -> str:
    # First check CHROME_BIN environment variable (standard in cloud buildpacks/Docker)
    env_bin = os.environ.get("CHROME_BIN") or os.environ.get("CHROME_PATH")
    if env_bin and os.path.exists(env_bin):
        return env_bin

    for path in CHROME_PATHS:
        if os.path.exists(path):
            return path

    # Check via shutil.which for PATH entries on Linux
    import shutil
    for cmd in ["google-chrome", "chromium", "chromium-browser", "chrome"]:
        w = shutil.which(cmd)
        if w:
            return w

    return None

def capture_screenshot(target_url: str, output_dir: str = "frontend/screenshots", timeout: int = 10) -> dict:
    """
    Renders target_url using headless Chromium and saves screenshot to output_dir.
    Returns metadata including file path, url, and capture status.
    """
    browser_exe = find_browser_executable()
    if not browser_exe:
        return {
            "success": False,
            "error": "No headless browser (Chrome or Edge) executable found on host system.",
            "screenshot_path": None,
            "relative_url": None
        }

    os.makedirs(output_dir, exist_ok=True)
    
    # Generate unique deterministic filename based on URL hash
    url_hash = hashlib.md5(target_url.encode()).hexdigest()[:12]
    filename = f"capture_{url_hash}.png"
    abs_output_path = os.path.abspath(os.path.join(output_dir, filename))
    relative_url = f"/screenshots/{filename}"

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
        # Run headless browser process
        subprocess.run(args, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Verify file exists and has content
        if os.path.exists(abs_output_path) and os.path.getsize(abs_output_path) > 1000:
            return {
                "success": True,
                "screenshot_path": abs_output_path,
                "relative_url": relative_url,
                "file_size": os.path.getsize(abs_output_path),
                "error": None
            }
        else:
            return {
                "success": False,
                "error": "Screenshot file was not generated or target timed out during rendering.",
                "screenshot_path": None,
                "relative_url": None
            }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Headless browser timed out after {timeout}s while attempting to render {target_url}.",
            "screenshot_path": None,
            "relative_url": None
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "screenshot_path": None,
            "relative_url": None
        }
