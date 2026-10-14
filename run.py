"""
Protocol Mimicry Engine - Single Startup Script.
Launches the Flask backend server on 127.0.0.1:5000 and automatically opens the browser.
"""

import sys
import time
import webbrowser
import threading
from backend.app import app
from backend.config import ensure_directories

def open_browser():
    """Wait briefly for server to bind, then open the laboratory interface."""
    time.sleep(1.0)
    webbrowser.open("http://127.0.0.1:5000")

def main():
    ensure_directories()
    print("=" * 68)
    print("  PROTOCOL MIMICRY ENGINE - CONTROLLED TRAFFIC ANALYSIS LABORATORY")
    print("=" * 68)
    print("  [+] Status:         Engine Initialized")
    print("  [+] Host:           127.0.0.1 (Strict Localhost Loopback Guard Active)")
    print("  [+] Port:           5000")
    print("  [+] Interface:      http://127.0.0.1:5000")
    print("  [+] Safety:         No raw sockets, no packet injection, loopback only")
    print("=" * 68)
    print("  Press Ctrl+C to terminate the laboratory server.")
    print("=" * 68)

    # Launch browser opener thread
    threading.Thread(target=open_browser, daemon=True).start()

    # Start Flask server
    app.run(host="127.0.0.1", port=5000, debug=False)

if __name__ == "__main__":
    main()
