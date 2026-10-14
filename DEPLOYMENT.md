# Protocol Mimicry Engine - Production Deployment & JSON Persistence Guide

This guide provides complete instructions for deploying the **Protocol Mimicry Engine — Controlled Traffic Analysis Laboratory** using a decoupled production architecture:
1. **Frontend on Vercel**: High-performance static hosting at the edge.
2. **Backend on Render (or Railway / Docker VPS)**: Long-running persistent Python web service supporting real TCP/UDP socket telemetry over loopback (`127.0.0.1`) and structured atomic JSON storage.

---

## 1. Architectural Overview

```
 [ Browser Client ]
         │
         ├─── Static Assets (HTML/CSS/JS/Chart.js) ──► [ Vercel Edge Network ]
         │                                              (Configured via vercel.json)
         │
         └─── REST API / Telemetry Events ───────────► [ Python Networking Backend ]
                                                        (Flask + Gunicorn + Atomic JSON Engine)
                                                              │
                                                        [ 127.0.0.1 Loopback ]
                                                        Real TCP/UDP Experiments
                                                              │
                                                        [ Structured Datasets & Uploads ]
                                                        data/storage/*.json & data/uploads/*
```

### Why Decoupled with Persistent JSON Storage?
- **Real Networking Telemetry**: The engine creates real TCP stream sockets and UDP datagram sockets over loopback (`127.0.0.1`) to record inter-packet arrival times, sizes, jitter, and burstiness. Serverless hosts cannot reliably run raw socket servers or long-running stream generators.
- **Pure Structured JSON Storage**: The application requires **zero external or SQL database dependencies**. All transferred files, analysis results, mimicry experiments, lab configurations, and audit event logs are persisted in clean, portable JSON datasets.
- **High Concurrency & Atomicity**: Writes are protected by dataset-level `threading.RLock` mutual exclusion and executed atomically using `tempfile.mkstemp`, `os.replace`, and disk `fsync`. Malformed files are automatically backed up to timestamped `.bak` files and self-healed.
- **Edge Performance**: Vercel serves the static HTML/CSS/JS instantly with global CDN caching.

---

## 2. Persistent JSON Storage Datasets

The backend organizes all persistent state into 5 structured JSON datasets inside `data/` (or configured via `STORAGE_DIR`), and stores underlying binary files inside `data/uploads/` (or configured via `UPLOADS_DIR`):

| Dataset File | Description | Key Schema Attributes |
| :--- | :--- | :--- |
| `transferred_files.json` | Complete metadata for all files transferred over loopback sockets. | `file_id`, `original_filename`, `extension`, `mime_type`, `size_bytes`, `sha256`, `received_sha256`, `integrity_verified`, `transport_protocol`, `source_label`, `dest_label`, `storage_path`, `duration_ms`, `status`, `analysis_id`, `experiment_id` |
| `analysis_results.json` | Statistical features extracted from packet flows and heuristic DPI classification scores. | `analysis_id`, `file_id`, `experiment_id`, `stage`, `transport_protocol`, `packet_count`, `total_bytes`, `mean_size`, `size_std_dev`, `min_size`, `max_size`, `mean_ipt_ms`, `ipt_std_dev_ms`, `jitter_ms`, `throughput_kbps`, `classifier_result`, `classifier_config_version`, `analysis_timestamp`, `execution_status` |
| `experiments.json` | Complete experimental mimicry runs with baseline vs. transformed comparisons. | `id`, `file_id`, `analysis_before_id`, `analysis_after_id`, `created_at`, `status`, `config`, `features_before`, `features_after`, `classification_before`, `classification_after`, `mimicry_config`, `comparison`, `original_checksum`, `transformed_checksum`, `content_integrity_verified` |
| `lab_details.json` | Versioned laboratory configuration, safety guard status, and classifier weights. | `lab_name`, `version`, `status`, `safety_guard`, `supported_transports`, `storage_engine`, `datasets`, `classifier_profiles`, `classifier_config`, `limits`, `created_at`, `updated_at` |
| `transfer_logs.json` | Append-only audit trail logging socket transmissions, uploads, deletions, and errors. | `event_id`, `event_type`, `status`, `message`, `timestamp`, `file_id`, `experiment_id`, `details`, `error` |

### Actual Binary File Storage
Uploaded files are stored in `data/uploads/<file_id>_<sanitized_filename>`. Filenames are strictly sanitized with path traversal checks (`..`, `/`, `\`) to prevent directory escape. JSON metadata references the stored file path for authorized retrieval.

---

## 3. Deploying the Backend (Render / Railway / VPS)

Render is recommended because it supports persistent disks, custom ports, and long-running Python processes.

### Deploying via Render Blueprint
1. Push this repository to your GitHub account (`SanthoskrishnaG/Chameleon_Net`).
2. Log into the [Render Dashboard](https://dashboard.render.com).
3. Click **New +** > **Blueprint**.
4. Connect your `Chameleon_Net` repository.
5. Render will automatically read `render.yaml` and configure:
   - **Service Name**: `protocol-mimicry-engine`
   - **Runtime**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn backend.app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120`
   - **Health Check Path**: `/api/health`
   - **Persistent Disk**: 1 GB mounted at `/var/data`
   - **Environment Variables**: `STORAGE_DIR=/var/data/storage`, `UPLOADS_DIR=/var/data/uploads`
6. Provide your frontend Vercel URL in `ALLOWED_ORIGINS`.
7. Click **Apply**.

---

## 4. Deploying the Frontend (Vercel)

The repository includes root `vercel.json` and `web/vercel.json` with clean URL rewrites for:
- `/dashboard` -> `web/dashboard.html`
- `/files` -> `web/files.html`
- `/logs` -> `web/logs.html`
- `/generator` -> `web/generator.html`
- `/features` -> `web/features.html`
- `/classifier` -> `web/classifier.html`
- `/mimicry` -> `web/mimicry.html`
- `/comparison` -> `web/comparison.html`
- `/results` -> `web/results.html`
- `/settings` -> `web/settings.html`
- `/demo` -> `web/demo.html`

### Deploying via Vercel Dashboard
1. Log into [Vercel](https://vercel.com).
2. Click **Add New...** > **Project** and import your repository.
3. In **Project Configuration**, leave Framework Preset as `Other` and Root Directory as `./`.
4. Click **Deploy**.
5. Once deployed, open **Settings & Weights** in the dashboard UI, enter your Render backend URL, and click **Test Connection** & **Save Backend Settings**.

---

## 5. Backup and Restore Procedures

Because all state is stored cleanly in JSON files and binary uploads, backing up and restoring the engine is fast and deterministic.

### Automated Backup Command
Run the backup script or shell command to archive all persistent datasets and uploaded binary files:
```bash
# Create a timestamped backup archive
BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
tar -czvf "backup_mimicry_storage_${BACKUP_DATE}.tar.gz" data/storage data/uploads
```

### Automated Restore Command
To restore datasets from an archive:
```bash
# 1. Stop the backend process
# 2. Extract the archive into the data root
tar -xzvf backup_mimicry_storage_YYYYMMDD_HHMMSS.tar.gz -C ./

# 3. Verify dataset integrity
python -c "from backend.json_storage import get_lab_details, list_transferred_files; print('Lab:', get_lab_details()['lab_name']); print('Files:', list_transferred_files()['total'])"

# 4. Restart the backend process
```

### Disaster Recovery & Self-Healing
If a JSON file becomes corrupted due to a host crash or sudden power failure:
1. The engine automatically detects malformed JSON on read.
2. It renames the broken file to `<dataset>_corrupt_<timestamp>.bak` so data is never lost.
3. It initializes a clean dataset structure and logs a high-priority event to `transfer_logs.json`.
4. The administrator can inspect the `.bak` file or restore from the latest backup tarball.

---

## 6. Environment Variables Reference

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `PORT` | `5000` | Port for the HTTP API server. |
| `HOST` | `127.0.0.1` / `0.0.0.0` | Host interface. Set to `0.0.0.0` in cloud hosting to receive public traffic. |
| `DEPLOYMENT_MODE` | `false` | When `true`, enables production security defaults and CORS protections. |
| `STRICT_LOCAL_IP_GUARD` | `true` in local, `false` in cloud | When `true`, blocks incoming HTTP requests from non-loopback IP addresses. Must be `false` on cloud hosts. |
| `ALLOWED_ORIGINS` | *(localhost)* | Comma-separated list of approved frontend origins allowed by CORS. |
| `ALLOW_VERCEL_PREVIEWS` | `true` | Allows preview deployment URLs matching `https://*.vercel.app`. |
| `API_KEY` | *(empty)* | Optional secret key. When set, mutating endpoints require header `X-API-Key`. |
| `DATA_DIR` | `data` | Directory where experiments and traffic CSVs are stored. |
| `STORAGE_DIR` | `data/storage` | Persistent directory for the 5 structured JSON datasets. |
| `UPLOADS_DIR` | `data/uploads` | Persistent directory for binary/uploaded payload files. |
| `MAX_FILE_SIZE_BYTES` | `10485760` (10 MB) | Maximum upload file size in bytes. |
| `MAX_ACTIVE_EXPERIMENTS` | `3` | Maximum concurrent background experiment processes. |
| `MAX_PACKET_COUNT` | `1000` | Maximum allowable packets in a single traffic generation request. |
| `MAX_PACKET_SIZE` | `1500` | Maximum bytes per packet (bounded by standard MTU). |

---

## 7. Security and Safety Guarantees

1. **Loopback-Only Telemetry Isolation**: Real TCP and UDP transmissions strictly use `127.0.0.1`. The engine will never transmit packets to external internet IPs or internal LAN hosts. Arbitrary destination addresses are rejected with HTTP 400.
2. **Zero SQL Injection Risk**: Pure JSON file persistence eliminates SQL injection attack surfaces entirely.
3. **Path Traversal Protection**: Filenames and record IDs are sanitized with regex validation and checked with `os.path.resolve()`. Any path outside `UPLOADS_DIR` or `STORAGE_DIR` is rejected with HTTP 403.
4. **Content-Integrity Verification**: Transferred files have SHA-256 computed from raw bytes before transmission and recomputed after socket reassembly, verifying 100% bit-exact transmission.
5. **No Wildcard CORS with Credentials**: CORS only allows explicitly approved origins and validated `*.vercel.app` preview URLs.
