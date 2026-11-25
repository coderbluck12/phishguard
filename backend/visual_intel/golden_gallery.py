"""
Golden Brand Template Visual Gallery Generator.
Generates baseline layout templates for popular high-target brands:
- Apple ID
- PayPal
- Microsoft 365
- Google Account
Used by the Siamese Visual Comparator to measure perceptual layout similarity.
"""
import os
import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "golden_templates")

def create_apple_golden_template(path: str):
    img = Image.new("RGB", (1280, 800), "#f5f5f7")
    draw = ImageDraw.Draw(img)
    
    # White card in center
    cx, cy = 640, 400
    w, h = 420, 460
    draw.rounded_rectangle([cx - w//2, cy - h//2, cx + w//2, cy + h//2], radius=18, fill="#ffffff", outline="#e5e5ea", width=1)
    
    # Apple logo mock
    draw.ellipse([cx - 20, cy - 180, cx + 20, cy - 140], fill="#1d1d1f")
    # Title bar
    draw.rectangle([cx - 100, cy - 110, cx + 100, cy - 85], fill="#333333")
    # Inputs
    draw.rounded_rectangle([cx - 160, cy - 50, cx + 160, cy - 5], radius=8, outline="#d2d2d7", width=2)
    draw.rounded_rectangle([cx - 160, cy + 15, cx + 160, cy + 60], radius=8, outline="#d2d2d7", width=2)
    # Blue Button
    draw.rounded_rectangle([cx - 160, cy + 85, cx + 160, cy + 130], radius=8, fill="#0071e3")
    
    img.save(path)

def create_paypal_golden_template(path: str):
    img = Image.new("RGB", (1280, 800), "#f4f6f8")
    draw = ImageDraw.Draw(img)
    
    cx, cy = 640, 400
    w, h = 400, 480
    draw.rounded_rectangle([cx - w//2, cy - h//2, cx + w//2, cy + h//2], radius=12, fill="#ffffff", outline="#e1e7ec", width=1)
    
    # PayPal dark blue logo bar
    draw.rectangle([cx - 80, cy - 180, cx + 80, cy - 140], fill="#003087")
    # Form input boxes
    draw.rounded_rectangle([cx - 150, cy - 70, cx + 150, cy - 25], radius=6, outline="#cbd5e1", width=2)
    draw.rounded_rectangle([cx - 150, cy - 10, cx + 150, cy + 35], radius=6, outline="#cbd5e1", width=2)
    # PayPal rounded pill button
    draw.rounded_rectangle([cx - 150, cy + 70, cx + 150, cy + 120], radius=25, fill="#0070ba")
    
    img.save(path)

def create_microsoft_golden_template(path: str):
    img = Image.new("RGB", (1280, 800), "#eef2f5")
    draw = ImageDraw.Draw(img)
    
    cx, cy = 640, 400
    w, h = 440, 400
    draw.rectangle([cx - w//2, cy - h//2, cx + w//2, cy + h//2], fill="#ffffff", outline="#d1d5db", width=1)
    
    # MS 4-color square logo
    draw.rectangle([cx - 170, cy - 150, cx - 152, cy - 132], fill="#f25022")
    draw.rectangle([cx - 150, cy - 150, cx - 132, cy - 132], fill="#7fba00")
    draw.rectangle([cx - 170, cy - 130, cx - 152, cy - 112], fill="#00a4ef")
    draw.rectangle([cx - 150, cy - 130, cx - 132, cy - 112], fill="#ffb900")
    
    # Title
    draw.rectangle([cx - 170, cy - 90, cx + 50, cy - 65], fill="#111827")
    # Input
    draw.line([cx - 170, cy + 10, cx + 170, cy + 10], fill="#0067b8", width=2)
    # Button
    draw.rectangle([cx + 60, cy + 60, cx + 170, cy + 100], fill="#0067b8")
    
    img.save(path)

def init_golden_templates():
    os.makedirs(TEMPLATES_DIR, exist_ok=True)
    apple_path = os.path.join(TEMPLATES_DIR, "apple.png")
    paypal_path = os.path.join(TEMPLATES_DIR, "paypal.png")
    ms_path = os.path.join(TEMPLATES_DIR, "microsoft.png")

    if not os.path.exists(apple_path):
        create_apple_golden_template(apple_path)
    if not os.path.exists(paypal_path):
        create_paypal_golden_template(paypal_path)
    if not os.path.exists(ms_path):
        create_microsoft_golden_template(ms_path)

if __name__ == "__main__":
    init_golden_templates()
    print("Golden brand templates initialized successfully in:", TEMPLATES_DIR)
