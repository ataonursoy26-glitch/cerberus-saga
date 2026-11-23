# Cerberus Saga — isolated deployment image (Blueprint Volume 6)
FROM python:3.12-slim

# Scanner binaries (optional; modules fall back without them)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap git curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
EXPOSE 8000

# Default: start the SaaS API gateway
CMD ["uvicorn", "web_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
