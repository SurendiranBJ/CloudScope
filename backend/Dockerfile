FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user
RUN groupadd -g 1001 cloudscope && \
    useradd -u 1001 -g cloudscope -m -s /bin/bash cloudscope

COPY . .
RUN chown -R cloudscope:cloudscope /app

USER cloudscope

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

