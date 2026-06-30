# ── AntiPhishing Server ───────────────────────────────────────────────────────
# Python 3.11 slim — small image, fast builds
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Install system dependencies needed by some Python packages
# - gcc: needed for compiling some Python packages
# - whois: command-line whois tool (backup for python-whois)
RUN apt-get update && apt-get install -y \
    gcc \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first — Docker caches this layer
# so pip install only re-runs when requirements.txt changes
COPY requirements.txt .

# Install all Python dependencies including ML packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project into the container
COPY . .

# The ML model is at ml/model.pkl inside the container
# app.py looks for it at ../ml/model.pkl relative to scripts/app.py
# which resolves to /app/ml/model.pkl — correct

# Expose Flask port
EXPOSE 5000

# Default command — run the Flask server
# docker-compose.yml overrides this per service
CMD ["python", "scripts/app.py"]
