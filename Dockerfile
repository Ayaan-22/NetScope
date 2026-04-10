# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Install nmap (system package) and build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
COPY . .

# Non-root user for security
RUN groupadd -r netscope && useradd -r -g netscope netscope \
    && mkdir -p reports logs \
    && chown -R netscope:netscope /app

USER netscope

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
