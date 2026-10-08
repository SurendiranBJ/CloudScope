# CloudScope Deployment Guide

## 1. Architecture Overview
CloudScope is packaged as modular OCI containers orchestrated via Docker Compose or Kubernetes.

```
                    ┌─────────────────────────┐
                    │     Frontend Nginx      │
                    │       (Port 80)         │
                    └────────────┬────────────┘
                                 │
                     HTTP /api/v1 (Proxied)
                                 │
                    ┌────────────▼────────────┐
                    │      FastAPI App        │
                    │  (Port 8000, Non-Root)  │
                    └──────┬───────────┬──────┘
                           │           │
          ┌────────────────▼────┐   ┌──▼──────────────────┐
          │     Redis 7         │   │   Neo4j 5 Graph DB  │
          │ (Internal Network)  │   │  (Internal Network) │
          └─────────────────────┘   └─────────────────────┘
```

## 2. Docker Consolidation & Hardening
- **Root Dockerfile (`backend/Dockerfile`)**:
  - Base: `python:3.11-slim`
  - Non-root user: `cloudscope` (UID 1001, GID 1001)
  - Packages: minimal build dependencies cleaned up after installation; includes `curl` for container healthcheck.
- **Frontend Dockerfile (`frontend/Dockerfile`)**:
  - Stage 1: `node:22-alpine` building optimized Vite bundle (`tsc -b && vite build`)
  - Stage 2: `nginx:alpine` serving static SPA assets with custom gzip and route handling.
- **Network Isolation**:
  - `cloudscope-internal`: Private bridge network with no external port mapping for Redis. Neo4j Bolt is bound only to `127.0.0.1` on the host in development.
  - `cloudscope-public`: Bridge network exposing ports 80 (Frontend) and 8000 (Backend API).

## 3. Configuration Reference (`.env`)

| Variable | Description | Required | Default |
| :--- | :--- | :---: | :--- |
| `NEO4J_USER` | Neo4j database username | No | `neo4j` |
| `NEO4J_PASSWORD` | Neo4j database password | **Yes (Prod)** | None in prod |
| `REDIS_HOST` | Redis hostname | No | `redis` |
| `REDIS_PORT` | Redis port | No | `6379` |
| `DATABASE_URL` | Relational DB URL | No | `sqlite:////app/storage/cloudscope.db` |
| `JWT_SECRET` | Secret key for JWT verification | **Yes (Prod)** | None in prod |
| `DEV_AUTH_MODE` | Enable dev header auth (`X-Dev-Role`) | No | `false` |
| `AWS_PROFILE` | AWS credentials profile name | No | `identityscope-scanner` |
| `AWS_DEFAULT_REGION`| Default regional scan target | No | `us-east-1` |
| `AI_PROVIDER` | AI provider for Copilot (`gemini`) | No | `gemini` |
| `GEMINI_API_KEY` | Google Gemini API key | If AI enabled | None |

## 4. Running Locally (Development)
```bash
# Start all services with local development defaults
docker compose -f compose.yaml up --build
```

## 5. Running in Production
```bash
# 1. Populate secrets in .env
cp .env.example .env
# Edit .env with strong NEO4J_PASSWORD, JWT_SECRET, GEMINI_API_KEY

# 2. Launch production stack with released immutable images
docker compose -f compose.release.yaml pull
docker compose -f compose.release.yaml up -d
```
