# VAJRA Unified Backend API

High-speed backend for the VAJRA Cyber-Reasoning Web & Desktop System.

## Features
- **Smart Intent Router**: Automatically directs general questions to the LLM (bypassing slow finder scans) and activates the 3-stage AST pipeline only for security audits.
- **Multi-Provider Support**: Connects to **Groq Cloud (Free, 300+ tok/s)**, **HuggingFace Inference API**, **OpenAI-compatible endpoints**, or **Local Ollama**.
- **CORS Enabled**: Out-of-the-box support for browser clients and Tauri desktop apps.

## Running Locally
```bash
pip install -r requirements.txt
python server.py
```

## Free Cloud Deployment (1-Click)

### 1. Render.com
1. Create a free account at [render.com](https://render.com).
2. Click **New Web Service** and link your GitHub repo (`VAJRA`).
3. Root Directory: `backend` (or leave root).
4. Build Command: `pip install -r backend/requirements.txt`
5. Start Command: `python backend/server.py`
6. (Optional) Set Environment Variable `GROQ_API_KEY` for free high-speed cloud inference!

### 2. Hugging Face Spaces
1. Create a new Space on [Hugging Face](https://huggingface.co/spaces) with SDK: **Docker** or **Gradio/FastAPI**.
2. Upload the `backend/` files and set `HF_TOKEN` in Space secrets.
