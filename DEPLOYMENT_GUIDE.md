# Complete Free Deployment Guide for PhishGuard

This guide outlines the top 3 recommended platforms for deploying **PhishGuard** completely free of charge, with live HTTPS URLs and zero hosting cost.

---

## 🏆 Option 1: Render.com (Recommended — Simplest Free Deployment)

[Render](https://render.com) offers **Free Web Services** that natively connect to your GitHub repository and automatically build and deploy Python FastAPI apps.

### Step-by-Step Instructions:
1. **Push your code to GitHub**:
   ```bash
   git init
   git add .
   git commit -m "Deploy PhishGuard with ML and Siamese Visual Engine"
   git branch -M main
   git remote add origin https://github.com/<YOUR_USERNAME>/phishguard.git
   git push -u origin main
   ```
2. **Sign up / Log in to [Render.com](https://render.com)** (Free tier, no credit card required).
3. Click **"New +"** $\to$ **"Web Service"**.
4. Connect your GitHub repository.
5. In the configuration settings:
   - **Name**: `phishguard-ai` (or any custom name)
   - **Environment**: `Python 3`
   - **Region**: Choose the closest region (e.g. Frankfurt, Oregon, Ohio)
   - **Branch**: `main`
   - **Build Command**: `pip install -r requirements.txt && python -m backend.visual_intel.golden_gallery && python -m backend.visual_intel.golden_gallery_extended`
   - **Start Command**: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type**: Select **"Free"**
6. Click **"Deploy Web Service"**.
   - Within 2–3 minutes, your platform is live at:  
     `https://phishguard-ai.onrender.com` (with free automatic SSL/TLS).

---

## 🚀 Option 2: Hugging Face Spaces (Best for AI & Vision Models)

[Hugging Face Spaces](https://huggingface.co/spaces) offers **free, permanent 16 GB RAM + 2 vCPU Docker container hosting** that never sleeps or spins down. Because PhishGuard runs a trained machine learning ensemble and headless Chromium, Hugging Face Spaces is a premier free host.

### Step-by-Step Instructions:
1. Go to [Hugging Face Spaces](https://huggingface.co/new-space) and create a free account.
2. Click **"Create new Space"**:
   - **Space name**: `phishguard-sentinel`
   - **License**: `mit`
   - **Space SDK**: Select **"Docker"** (Blank template)
   - **Visibility**: `Public`
3. Clone the new Space locally or push this repository directly:
   ```bash
   git remote add hf https://huggingface.co/spaces/<YOUR_USERNAME>/phishguard-sentinel
   git push -u hf main
   ```
4. The included [Dockerfile](file:///c:/Users/Admin/phisher/Dockerfile) automatically installs Chromium, loads Python dependencies, compiles the templates, and starts the service.
5. Your platform is instantly accessible worldwide at:  
   `https://<YOUR_USERNAME>-phishguard-sentinel.hf.space`

---

## ⚡ Option 3: Railway.app / Koyeb

Both [Railway.app](https://railway.app) and [Koyeb.com](https://www.koyeb.com) provide free container runtime credits:
1. Connect your GitHub repository.
2. Select **Dockerfile** deployment (Railway automatically detects the root `Dockerfile`).
3. Set the exposed port to `8000`.
4. Deploy with one click.

---

## 🌐 Local / Instant Public Demonstration (Ngrok / Cloudflare Tunnel)

If you need an instant public HTTPS link right now from your workstation for a class or client demo without pushing to a cloud service:

```bash
# Using Cloudflare Tunnel (100% Free, No Account Needed)
winget install --id Cloudflare.cloudflared
cloudflared tunnel --url http://127.0.0.1:8000
```
This generates an instant secure public URL (e.g. `https://random-subdomain.trycloudflare.com`) routing directly to your running PhishGuard server.
