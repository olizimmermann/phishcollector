# Pin to Bookworm (Debian 12): Trixie (13) removed font packages playwright --with-deps expects
FROM python:3.12-slim-bookworm

# Chromium system dependencies — installed manually so we control the package list
# and avoid Playwright's --with-deps which references Trixie-unavailable fonts.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget curl \
    libnss3 libnspr4 libdbus-1-3 \
    libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libasound2 libxshmfence1 \
    libx11-6 libxext6 libxcb1 libxi6 libxtst6 libxss1 \
    fonts-liberation fonts-noto-color-emoji fonts-unifont \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Chromium browser binary only (deps already handled above)
RUN playwright install chromium

COPY . .

# Persistent storage for screenshots, HTML dumps, and downloaded assets
RUN mkdir -p /data/screenshots /data/html /data/assets

EXPOSE 8000

CMD ["uvicorn", "phishcollector.main:app", "--host", "0.0.0.0", "--port", "8000"]
