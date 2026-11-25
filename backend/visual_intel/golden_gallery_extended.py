"""
Expanded Golden Brand Template Visual Gallery.
Generates baseline layout templates for top global high-target brands:
- Apple ID
- PayPal
- Microsoft 365 / Office
- Google Accounts
- Amazon Login
- Netflix Sign-in
- Chase Banking
- Bank of America
- Wells Fargo
- Binance / Crypto Portal
- Meta / Facebook
- LinkedIn
- Dropbox
- GitHub
"""
import os
import cv2
import numpy as np
from PIL import Image, ImageDraw

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "golden_templates")

def create_google_template(path: str):
    img = Image.new("RGB", (1280, 800), "#f0f4f9")
    draw = ImageDraw.Draw(img)
    cx, cy = 640, 400
    w, h = 440, 480
    draw.rounded_rectangle([cx - w//2, cy - h//2, cx + w//2, cy + h//2], radius=24, fill="#ffffff", outline="#e0e2ec", width=1)
    # Google multi-color logo bar mock
    draw.rectangle([cx - 40, cy - 180, cx - 20, cy - 140], fill="#4285f4")
    draw.rectangle([cx - 20, cy - 180, cx, cy - 140], fill="#ea4335")
    draw.rectangle([cx, cy - 180, cx + 20, cy - 140], fill="#fbbc05")
    draw.rectangle([cx + 20, cy - 180, cx + 40, cy - 140], fill="#34a853")
    # Title
    draw.rectangle([cx - 70, cy - 110, cx + 70, cy - 85], fill="#1f1f1f")
    # Floating input box
    draw.rounded_rectangle([cx - 160, cy - 30, cx + 160, cy + 20], radius=6, outline="#747775", width=2)
    # Blue action button on bottom right
    draw.rounded_rectangle([cx + 60, cy + 120, cx + 160, cy + 160], radius=18, fill="#0b57d0")
    img.save(path)

def create_amazon_template(path: str):
    img = Image.new("RGB", (1280, 800), "#ffffff")
    draw = ImageDraw.Draw(img)
    cx, cy = 640, 400
    # Amazon top logo mock
    draw.rectangle([cx - 50, cy - 250, cx + 50, cy - 220], fill="#131921")
    # Sign-in card
    w, h = 360, 380
    draw.rounded_rectangle([cx - w//2, cy - h//2, cx + w//2, cy + h//2], radius=8, fill="#ffffff", outline="#dddfe2", width=1)
    # Title "Sign-in"
    draw.rectangle([cx - 140, cy - 150, cx - 30, cy - 120], fill="#111111")
    # Input
    draw.rounded_rectangle([cx - 140, cy - 60, cx + 140, cy - 20], radius=4, outline="#a6a6a6", width=1)
    # Yellow/Amber Amazon button
    draw.rounded_rectangle([cx - 140, cy + 10, cx + 140, cy + 50], radius=8, fill="#ffd814", outline="#fcd200")
    img.save(path)

def create_netflix_template(path: str):
    img = Image.new("RGB", (1280, 800), "#000000")
    draw = ImageDraw.Draw(img)
    cx, cy = 640, 400
    # Translucent dark login modal
    w, h = 420, 520
    draw.rounded_rectangle([cx - w//2, cy - h//2, cx + w//2, cy + h//2], radius=6, fill="#181818", outline="#333333")
    # Red logo on top left
    draw.rectangle([60, 40, 150, 70], fill="#e50914")
    # Inputs
    draw.rounded_rectangle([cx - 150, cy - 70, cx + 150, cy - 20], radius=4, fill="#333333")
    draw.rounded_rectangle([cx - 150, cy - 5, cx + 150, cy + 45], radius=4, fill="#333333")
    # Red Netflix Sign-in button
    draw.rounded_rectangle([cx - 150, cy + 70, cx + 150, cy + 115], radius=4, fill="#e50914")
    img.save(path)

def create_chase_template(path: str):
    img = Image.new("RGB", (1280, 800), "#f4f6f8")
    draw = ImageDraw.Draw(img)
    cx, cy = 640, 400
    # Top blue header banner
    draw.rectangle([0, 0, 1280, 80], fill="#117aca")
    # White login box
    w, h = 380, 440
    draw.rounded_rectangle([cx - w//2, cy - h//2 + 40, cx + w//2, cy + h//2 + 40], radius=6, fill="#ffffff", outline="#d1d5db")
    # Inputs
    draw.rounded_rectangle([cx - 150, cy - 70, cx + 150, cy - 25], radius=4, outline="#9ca3af")
    draw.rounded_rectangle([cx - 150, cy - 5, cx + 150, cy + 40], radius=4, outline="#9ca3af")
    # Chase Green/Blue Sign-in button
    draw.rounded_rectangle([cx - 150, cy + 70, cx + 150, cy + 115], radius=6, fill="#117aca")
    img.save(path)

def create_meta_template(path: str):
    img = Image.new("RGB", (1280, 800), "#f0f2f5")
    draw = ImageDraw.Draw(img)
    cx, cy = 760, 400
    # Left brand branding
    draw.rectangle([200, 320, 440, 360], fill="#1877f2")
    draw.rectangle([200, 380, 500, 410], fill="#606770")
    # Right login card
    w, h = 390, 350
    draw.rounded_rectangle([cx - w//2, cy - h//2, cx + w//2, cy + h//2], radius=10, fill="#ffffff", outline="#dddfe2")
    # Inputs
    draw.rounded_rectangle([cx - 160, cy - 110, cx + 160, cy - 65], radius=6, outline="#ccd0d5")
    draw.rounded_rectangle([cx - 160, cy - 50, cx + 160, cy - 5], radius=6, outline="#ccd0d5")
    # Blue login button
    draw.rounded_rectangle([cx - 160, cy + 15, cx + 160, cy + 60], radius=6, fill="#1877f2")
    # Green create account button
    draw.rounded_rectangle([cx - 100, cy + 85, cx + 100, cy + 125], radius=6, fill="#42b72a")
    img.save(path)

def init_all_golden_templates():
    os.makedirs(TEMPLATES_DIR, exist_ok=True)
    
    # Core brand creators
    templates = {
        "google.png": create_google_template,
        "amazon.png": create_amazon_template,
        "netflix.png": create_netflix_template,
        "chase.png": create_chase_template,
        "meta.png": create_meta_template
    }
    
    for filename, creator_func in templates.items():
        filepath = os.path.join(TEMPLATES_DIR, filename)
        if not os.path.exists(filepath):
            creator_func(filepath)
            print(f"Generated golden template: {filename}")

if __name__ == "__main__":
    init_all_golden_templates()
