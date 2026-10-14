# Protocol Mimicry Engine - Controlled Traffic Analysis Laboratory

An educational computer-networks laboratory demonstrating how rule-based **Deep Packet Inspection (DPI)** classifiers identify network traffic purely from statistical side-channel features (packet size, arrival timing, flow volume, burst density, and jitter), and how controlled feature transformations (**protocol mimicry**) alter those classifications while preserving underlying user payloads.

---

## 1. Abstract

Modern network privacy tools operate under hostile network environments where Deep Packet Inspection (DPI) appliances examine side-channel features of encrypted streams. Even when payload content is encrypted with TLS 1.3, observable metadata—such as packet lengths and inter-packet arrival times (IPT)—leaks the identity of applications (e.g., distinguishing real-time VoIP from web browsing or bulk downloads).

This laboratory implements a **controlled protocol mimicry system** operating strictly over `127.0.0.1` localhost sockets. It demonstrates:
1. Statistical feature extraction from microsecond-precision socket transmissions.
2. A rule-based, explainable 5-dimension heuristic DPI classifier.
3. Three independent mimicry transformations (size padding, timing reshaping, and burst injection).
4. Physical re-transmission of transformed traffic over loopback sockets to measure real arrival distributions, true overhead costs, and lossless custom text recovery.

---

## 2. Safety & Ethical Constraints

- **Strict Loopback Binding:** The engine binds exclusively to `127.0.0.1` ephemeral socket ports. Any external host connection is rejected at the API middleware level (HTTP 403 Forbidden).
- **No Raw Sockets / No Packet Injection:** The software uses standard Python application sockets (`socket.AF_INET`, `socket.SOCK_STREAM` and `socket.SOCK_DGRAM`). No raw socket permissions or kernel drivers are used.
- **Educational Heuristic Model:** The classifier is an educational heuristic model designed for conceptual laboratory study, not a real firewall evasion tool. No real firewalls or third-party networks are targeted.

---

## 3. Architecture Overview

```
+-------------------------------------------------------------------------------------------------+
|                                  PROTOCOL MIMICRY LABORATORY                                    |
|                                                                                                 |
|   +-----------------------+              127.0.0.1 Sockets            +-----------------------+ |
|   |   Client Socket       | ========================================> |   Server Socket       | |
|   |   (Traffic Generator) |           (TCP / UDP Streams)             |   (Receiver/Reassembl)| |
|   +-----------------------+                                           +-----------------------+ |
|               |                                                                   |             |
|               v                                                                   v             |
|   +-----------------------+                                           +-----------------------+ |
|   |  CSV Trace Logger     | <---------------------------------------- | Padding Stripping     | |
|   |  (data/traffic/*.csv) |                                           | (Text Integrity Match)| |
|   +-----------------------+                                           +-----------------------+ |
|               |                                                                                 |
|               v                                                                                 |
|   +-----------------------+                                                                     |
|   | Feature Extractor     | ---> Mean/Std Size, Mean/Std IPT, Jitter, Bursts, Throughput        |
|   +-----------------------+                                                                     |
|               |                                                                                 |
|               v                                                                                 |
|   +-----------------------+                                                                     |
|   | Rule-Based Classifier | ---> Size, Timing, Volume, Burst/Jitter, Transport Rules (0-100%)   |
|   +-----------------------+                                                                     |
|               |                                                                                 |
|               v                                                                                 |
|   +-----------------------+                                                                     |
|   | Mimicry Engine        | ---> Size Padding, Delay Pacing, Burst Injection                    |
|   | (Loopback Re-send)    | =========================================================+          |
|   +-----------------------+                                                          |          |
|               |                                                                      |          |
|               v                                                                      v          |
|   +-----------------------------------------------------------------------------------------+   |
|   | Comparator Engine: Before vs After Deltas, Deception Verdict, and Overhead Accounting    |   |
|   +-----------------------------------------------------------------------------------------+   |
+-------------------------------------------------------------------------------------------------+
```

---

## 4. Module Directory Structure

```
protocol-mimicry-engine/
├── run.py                       # Single startup launcher (server + browser open)
├── requirements.txt             # Dependencies (Flask, flask-cors, pytest)
├── README.md                    # Academic documentation & lab guide
├── backend/
│   ├── config.py                # Loopback guard, storage directories, classifier settings
│   ├── profiles.py              # 5 educational application profiles
│   ├── text_payload.py          # Framing headers, UTF-8 chunking, padding markers, reassembly
│   ├── traffic_generator.py     # Socket server & client on 127.0.0.1, microsecond trace logger
│   ├── feature_extractor.py     # Size stats, IPT, jitter, burst clustering, rates
│   ├── dpi_classifier.py        # 5-rule explainable heuristic classifier with linear decay
│   ├── mimicry_engine.py        # Padding, timing reshaping, burst injection, loopback re-transmission
│   ├── comparator.py            # Feature deltas, deception verdict, overhead accounting
│   ├── result_store.py          # Experiment persistence, JSON, CSV, printable HTML report exports
│   └── app.py                  # Flask REST API and static asset server
├── web/
│   ├── index.html               # Redirects to dashboard
│   ├── dashboard.html           # Metric cards, pipeline overview, recent experiment runs
│   ├── generator.html           # Random pattern / custom text sender, live trace, packet flow canvas
│   ├── features.html            # Feature table, size histogram, IPT timeline, burst donut
│   ├── classifier.html          # Confidence gauge, rule contribution bars, profile evaluation matrix
│   ├── mimicry.html             # Profile cards, 3 toggles, sliders, loopback re-send, overhead meters
│   ├── comparison.html          # Before vs after cards, delta table, overlay chart, verdict banner
│   ├── results.html             # Filterable archive, search, sort, delete, exports
│   ├── demo.html                # Narrated live demo walkthrough with pause/speed controls
│   ├── settings.html            # Rule contribution weights and confidence threshold sliders
│   ├── css/
│   │   ├── style.css            # SaaS Light Theme design system
│   │   └── animations.css       # Flow animations, gauge transitions, skeleton shimmers
│   └── js/
│       ├── api.js               # REST client, toast notifications, counter animations
│       ├── nav.js               # Sidebar navigation, stage badges, pipeline stepper, health monitor
│       ├── charts.js            # Offline Chart.js wrappers & live canvas packet flow animation
│       ├── dashboard.js         # Dashboard controller
│       ├── generator.js         # Traffic generator & text chunking controller
│       ├── features.js          # Statistical feature charts controller
│       ├── classifier.js        # DPI classifier & gauge controller
│       ├── mimicry.js           # Mimicry transformation controller
│       ├── comparison.js        # Feature deltas & comparison controller
│       ├── results.js           # History archive controller
│       ├── demo.js              # Live automated walkthrough controller
│       ├── settings.js          # Settings & sliders controller
│       └── vendor/
│           └── chart.umd.min.js # Standalone Chart.js 4.4.1 (100% offline)
├── config/
│   └── classifier.json          # Classifier weights, tolerances, and thresholds
├── data/
│   ├── traffic/                 # Raw packet trace CSV logs
│   ├── features/                # Extracted feature JSON files
│   └── experiments/             # Complete experiment records
├── results/                     # Export directory
└── tests/
    └── test_all.py              # 17 comprehensive unit & integration pytest tests
```

---

## 5. Installation & Quick Start

### Prerequisites
- Python 3.10+ (tested on Python 3.10, 3.11, 3.12, 3.13)
- Windows PowerShell, Command Prompt, or Linux/macOS bash

### Installation
```bash
# Clone or navigate to the project directory
cd "c:\Users\keerthana\OneDrive\Desktop\CN 1"

# Install requirements
pip install -r requirements.txt
```

### Launch the Application
```bash
python run.py
```
`run.py` starts the Flask backend on `http://127.0.0.1:5000` and automatically opens the dashboard in your default browser.

### Run the Pytest Test Suite
```bash
pytest tests/test_all.py -v
```
All 17 tests verify loopback protection, socket transmissions, statistical features, classifier accuracy, mimicry padding, timing, custom text reassembly, and end-to-end demo execution.

---

## 6. How the Classifier Scores Traffic

The classifier evaluates flows against 5 educational profiles:
1. **HTTP-like Web Browsing (TCP):** Mean size 200–1400 B, IPT 30–300 ms, bursty think times.
2. **DNS-like Query Flow (UDP):** Mean size 60–200 B, short flows (2–25 packets), IPT 10–100 ms.
3. **VoIP-like Audio Stream (UDP):** Mean size 100–220 B, strict 18–22 ms cadence, jitter &lt; 5 ms.
4. **Video-Streaming-like (TCP):** Mean size 1000–1460 B, steady 5–15 ms cadence, long flows.
5. **Bulk-Transfer Baseline (TCP):** Mean size 400–700 B, paced 80–120 ms interval.

### Scoring Mechanics
Each rule computes a score between `0.0` and `1.0`:
- **Inside Expected Range:** Returns `1.0`.
- **Outside Expected Range:** Score decays linearly based on distance and tolerance:
  $$\text{Score} = \max\left(0.0, 1.0 - \frac{\text{Distance}}{\text{Tolerance}}\right)$$
- **Transport Rule:** Returns `1.0` if `packet.proto == profile.transport`, otherwise `0.0`.
- **Composite Confidence:**
  $$\text{Confidence \%} = \frac{\sum (w_i \times \text{Score}_i)}{\sum w_i} \times 100$$
- **Labels:** High ($\ge 80\%$), Moderate ($50\% - 79\%$), Low ($< 50\%$).

---

## 7. Custom Text Payload & Lossless Reassembly

Users can type custom text (up to 5,000 characters). The engine frames each packet with a 16-byte binary header:
```
+---------------+---------------+--------------------+------------------+----------------+
|  MAGIC (4B)   |  Seq Num (4B) | Total Chunks (4B)  | Data Length (2B) |   Flags (2B)   |
|   b'MIMC'     |   uint32      |      uint32        |     uint16       |     uint16     |
+---------------+---------------+--------------------+------------------+----------------+
```
- **Transparent Padding:** When size mimicry increases packet size to match VoIP or video profiles, random padding bytes are appended after the real text data.
- **Ordered Reassembly:** The server collects chunks by sequence number, reads exactly `data_len` bytes, and strips the padding.
- **UTF-8 Safety:** Chunks are reassembled into a single byte stream *before* decoding, guaranteeing zero character corruption even for multi-byte Unicode characters (e.g., emojis or Asian characters).

---

## 8. REST API Documentation

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check, engine status, loopback confirmation |
| `POST` | `/api/traffic/generate` | Starts real socket traffic generation on `127.0.0.1` |
| `GET` | `/api/traffic/<id>/status` | Polls progress (0-100%) and live packet trace |
| `POST` | `/api/text/preview` | Returns live chunk fragmentation preview |
| `GET` | `/api/features/<id>` | Retrieves extracted statistical features |
| `POST` | `/api/mimicry/apply` | Reshapes traffic & re-transmits across loopback sockets |
| `POST` | `/api/classify/<id>?stage=before\|after` | Runs 5-rule heuristic DPI classification |
| `GET` | `/api/compare/<id>` | Computes feature deltas, overhead, and deception verdict |
| `GET` | `/api/profiles` | Returns the 5 application profiles |
| `GET` | `/api/experiments` | Lists persisted experiment runs |
| `GET` | `/api/experiments/<id>` | Retrieves single experiment details |
| `DELETE`| `/api/experiments/<id>` | Deletes experiment and associated CSV traces |
| `GET` | `/api/export/<id>?format=csv\|json\|html` | Exports report in HTML, CSV, or JSON format |
| `GET` | `/api/settings` | Retrieves current classifier weights & thresholds |
| `PUT` | `/api/settings` | Updates or resets classifier weights |
| `POST` | `/api/demo/run` | Initiates automated live walkthrough |
| `GET` | `/api/demo/<run_id>/events` | Streams events for live walkthrough |

---

## 9. Frequently Asked Questions (Viva Voce)

1. **Why does encryption not hide application identity from statistical DPI?**
   Encryption conceals payload contents, but side-channel metrics (packet size, arrival timing, jitter, and burstiness) remain visible to network observers.
2. **What is the trade-off of protocol mimicry?**
   Applying dummy padding increases bandwidth consumption (extra bytes %), while timing delays reduce throughput.
3. **What is an honest protocol limitation?**
   If source traffic uses TCP but the target profile requires UDP, statistical mimicry of sizes and delays cannot deceive transport-layer inspection rules unless socket conversion is enabled.
#   C h a m e l e o n _ N e t  
 