FROM python:3.11-slim

WORKDIR /app

# Install curl for container healthcheck probe (/ready)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install production dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user and directories for persistent storage and AWS configuration
RUN groupadd -g 1001 cloudscope && \
    useradd -u 1001 -g cloudscope -m -s /bin/bash cloudscope && \
    mkdir -p /app/storage /app/data /home/cloudscope/.aws && \
    chown -R cloudscope:cloudscope /app /home/cloudscope

COPY . .
RUN mkdir -p /app/storage /app/data && \
    chown -R cloudscope:cloudscope /app

USER cloudscope

EXPOSE 8000

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ARG APP_VERSION=""
ENV APP_VERSION=${APP_VERSION}

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=\"*\""]
