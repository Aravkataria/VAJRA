# Dockerfile for VAJRA Autonomous Cyber-Reasoning & Verification System
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    VAJRA_STORAGE_BACKEND=memory

WORKDIR /app

# Install system dependencies (git for cloning public repos, curl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Expose web server port
EXPOSE 8000

# Run FastAPI server with Uvicorn
CMD ["sh", "-c", "uvicorn app.api:app --host 0.0.0.0 --port ${PORT:-8000}"]
