"""
Protocol Mimicry Engine - Single Startup Script.
Launches the Flask backend server for local development and opens the browser.
"""

import os
import sys
import time
import webbrowser
import threading
from backend.app import app
from backend.config import ensure_directories, HOST, PORT

def open_browser():
    """Wait briefly for server to bind, then open the laboratory interface."""
    time.sleep(1.2)
    url = f"http://127.0.0.1:{PORT}" if HOST in ("0.0.0.0", "127.0.0.1", "localhost") else f"http://{HOST}:{PORT}"
    try:
        webbrowser.open(url)
    except Exception:
        pass

def main():
    ensure_directories()
    display_host = "127.0.0.1" if HOST in ("0.0.0.0", "127.0.0.1") else HOST
    print("=" * 68)
    print("  PROTOCOL MIMICRY ENGINE - CONTROLLED TRAFFIC ANALYSIS LABORATORY")
    print("=" * 68)
    print("  [+] Status:         Engine Initialized")
    print(f"  [+] Bind Host:      {HOST}")
    print(f"  [+] Port:           {PORT}")
    print(f"  [+] Interface:      http://{display_host}:{PORT}")
    print("  [+] Safety:         Real TCP/UDP socket telemetry over 127.0.0.1 loopback")
    print("=" * 68)
    print("  Press Ctrl+C to terminate the laboratory server.")
    print("=" * 68)

    # Launch browser opener thread if not disabled
    if os.environ.get("NO_BROWSER", "").lower() not in ("true", "1"):
        threading.Thread(target=open_browser, daemon=True).start()

    # Start Flask development server
    app.run(host=HOST, port=PORT, debug=False)

if __name__ == "__main__":
    main()
