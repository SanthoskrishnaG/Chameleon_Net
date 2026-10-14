# Protocol Mimicry Engine - Production Deployment Guide

This guide provides instructions for deploying the **Protocol Mimicry Engine — Controlled Traffic Analysis Laboratory** using a decoupled production architecture:
1. **Frontend on Vercel**: High-performance static hosting at the edge.
2. **Backend on Render (or Railway / Docker VPS)**: Long-running persistent Python web service supporting real TCP/UDP socket telemetry over loopback (`127.0.0.1`).

---

## 1. Architectural Overview

```
 [ Browser Client ]
         │
         ├─── Static Assets (HTML/CSS/JS/Chart.js) ──► [ Vercel Edge Network ]
         │                                              (Configured via vercel.json)
         │
         └─── REST API / Telemetry Events ───────────► [ Render Web Service ]
                                                        (Flask + Gunicorn + SQLite)
                                                             │
                                                        [ 127.0.0.1 Loopback ]
                                                        Real TCP/UDP Experiments
```

### Why a Decoupled Architecture?
- **Real Networking Telemetry**: The engine creates real TCP and UDP sockets and transmits actual packets across loopback interfaces to record inter-packet arrival times, sizes, jitter, and burstiness. Serverless platforms (like pure Vercel serverless functions) cannot reliably run persistent raw socket servers or long-running stream generators.
- **Edge Performance**: Vercel serves the static HTML/CSS/JS instantly with global CDN caching.
- **State Persistence**: The backend uses an SQLite database (`experiments.db`) with Write-Ahead Logging (WAL) and disk-backed CSV/JSON mirrors, ensuring lab experiments are safely retained across restarts.

---

## 2. Deploying the Backend (Render)

Render is the recommended host because it supports long-running processes, custom ports, persistent disks, and native Python 3 environments.

### Option A: Using the Render Blueprint (Recommended)
1. Fork or push this repository to your GitHub account (`SanthoskrishnaG/Chameleon_Net`).
2. Log into the [Render Dashboard](https://dashboard.render.com).
3. Click **New +** > **Blueprint**.
4. Connect your `Chameleon_Net` repository.
5. Render will automatically detect `render.yaml` and configure:
   - **Service Name**: `protocol-mimicry-engine`
   - **Runtime**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn backend.app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120`
   - **Health Check Path**: `/api/health`
   - **Persistent Disk**: 1 GB mounted at `/var/data`
6. Provide your frontend Vercel URL in `ALLOWED_ORIGINS` (or edit after Vercel deployment).
7. Click **Apply**.

### Option B: Manual Web Service Setup on Render
1. In Render Dashboard, click **New +** > **Web Service**.
2. Connect your repository.
3. Configure settings:
   - **Environment**: `Python`
   - **Region**: Oregon or closest to your users
   - **Branch**: `main`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn backend.app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120`
4. Add **Environment Variables**:
   - `DEPLOYMENT_MODE` = `true`
   - `STRICT_LOCAL_IP_GUARD` = `false`
   - `ALLOWED_ORIGINS` = `https://your-app.vercel.app` (comma-separated if multiple)
   - `ALLOW_VERCEL_PREVIEWS` = `true`
   - `DATA_DIR` = `/var/data` (if using a disk) or `data`
   - `SQLITE_DB_PATH` = `/var/data/experiments.db` (or `data/experiments.db`)
   - `API_KEY` = *(optional strong secret)*
5. (Optional but recommended) Under **Disks**, add a disk:
   - **Name**: `mimicry-data`
   - **Mount Path**: `/var/data`
   - **Size**: 1 GB
6. Click **Create Web Service**. Note your backend URL (e.g., `https://protocol-mimicry-engine.onrender.com`).

---

## 3. Deploying the Frontend (Vercel)

The repository includes both root `vercel.json` and `web/vercel.json` to support zero-configuration deployments.

### Option A: Using the Vercel Web Dashboard (Recommended)
1. Log into [Vercel](https://vercel.com).
2. Click **Add New...** > **Project**.
3. Import your `Chameleon_Net` repository.
4. In **Project Configuration**:
   - **Framework Preset**: `Other`
   - **Root Directory**: `./` (leave default, `vercel.json` rewrites automatically route to `/web/`)
   - **Build & Output Settings**: Leave empty (no build step needed for vanilla JS).
5. (Optional) In **Environment Variables**, you can set:
   - `CHAMELEON_API_BASE_URL` = `https://protocol-mimicry-engine.onrender.com`
6. Click **Deploy**.

### Option B: Deploying via Vercel CLI
```bash
# Install Vercel CLI if needed
npm install -g vercel

# From repository root:
vercel deploy --prod
```

### Option C: Configuring Backend in Frontend UI
If you deploy the frontend before setting an environment variable, simply:
1. Open the deployed Vercel site.
2. Navigate to **Settings & Rule Weights** in the left sidebar.
3. Scroll to **3. Backend Service & Cloud Deployment Connection**.
4. Enter your Render backend URL (e.g., `https://protocol-mimicry-engine.onrender.com`).
5. (Optional) Enter your `API_KEY` if configured.
6. Click **Test Connection** to verify connectivity and latency.
7. Click **Save Backend Settings**. The configuration is stored in browser `localStorage` and will persist across all sessions!

---

## 4. Alternative Backend Hosting

### Docker / VPS Deployment
Use the included `Dockerfile`:
```bash
# Build the container
docker build -t chameleon-net .

# Run the container with persistent volume
docker run -d \
  --name mimicry-engine \
  -p 5000:5000 \
  -e DEPLOYMENT_MODE=true \
  -e STRICT_LOCAL_IP_GUARD=false \
  -e ALLOWED_ORIGINS=https://your-project.vercel.app \
  -v $(pwd)/data:/app/data \
  chameleon-net
```

### Railway Deployment
The repository includes `Procfile`. Simply connect the GitHub repository in Railway and add the environment variables from `.env.example`.

---

## 5. Environment Variables Reference

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `PORT` | `5000` | Port for the HTTP API server (set dynamically by Render/Railway). |
| `HOST` | `127.0.0.1` / `0.0.0.0` | Host interface. Set to `0.0.0.0` in cloud hosting to receive public traffic. |
| `DEPLOYMENT_MODE` | `false` | When `true`, enables production security defaults and CORS protections. |
| `STRICT_LOCAL_IP_GUARD` | `true` in local, `false` in cloud | When `true`, blocks incoming HTTP requests from non-loopback IP addresses. Must be `false` on cloud hosts. |
| `ALLOWED_ORIGINS` | *(localhost)* | Comma-separated list of approved frontend origins allowed by CORS. |
| `ALLOW_VERCEL_PREVIEWS` | `true` | Allows preview deployment URLs matching `https://*.vercel.app`. |
| `API_KEY` | *(empty)* | Optional secret key. When set, mutating endpoints require header `X-API-Key`. |
| `DATA_DIR` | `data` | Directory where experiments, traffic CSVs, and features are stored. |
| `SQLITE_DB_PATH` | `data/experiments.db` | Location of the SQLite database file. |
| `MAX_ACTIVE_EXPERIMENTS` | `3` | Maximum concurrent background experiment processes. |
| `MAX_PACKET_COUNT` | `1000` | Maximum allowable packets in a single traffic generation request. |
| `MAX_PACKET_SIZE` | `1500` | Maximum bytes per packet (bounded by standard MTU). |
| `MAX_TEXT_LENGTH` | `5000` | Maximum length in characters for custom text payload transmission. |

---

## 6. Security and Safety Guarantees

1. **Loopback-Only Telemetry Isolation**: Real TCP and UDP transmission always occurs strictly on `127.0.0.1`. The engine will never transmit packets to external internet IPs or internal LAN hosts. Arbitrary destination addresses are rejected with HTTP 400.
2. **Path Traversal Protection**: Experiment IDs are strictly validated using regex `^[a-zA-Z0-9_-]{1,64}$`. Directory traversal attempts (e.g. `../../etc/passwd`) are rejected with HTTP 400/404.
3. **No Wildcard CORS with Credentials**: CORS only allows explicitly approved origins and validated `*.vercel.app` preview URLs.
4. **Resilient Dual Storage**: Experiment index metadata is stored in SQLite (`experiments.db`) with WAL mode for crash recovery, alongside mirrored JSON/CSV records for raw packet analysis.
5. **Sanitized Error Responses**: Internal tracebacks and sensitive environment variables are never exposed in API responses.

---

## 7. Verification and Testing

### Run Automated Test Suite
From the project root:
```bash
python -m pytest -v
```
All 30+ tests will pass, verifying:
- Loopback guard and anti-proxy destination safety
- Real TCP and UDP packet generation
- Feature extraction (mean size, IPT, jitter, burstiness)
- DPI rule classification and mimicry transformation
- Reassembly equality and UTF-8 custom text integrity
- SQLite persistence across simulated restarts
- CORS origin authorization and API key enforcement

### Manual API Smoke Checks
```bash
# 1. Check health
curl -s https://your-backend.onrender.com/api/health

# 2. Test CORS with Origin
curl -I -X GET https://your-backend.onrender.com/api/health \
  -H "Origin: https://your-app.vercel.app"

# 3. List profiles
curl -s https://your-backend.onrender.com/api/profiles
```
