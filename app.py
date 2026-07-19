#!/usr/bin/env python3
"""
Makdi desktop launcher — wraps the crawler in a native window.
Build (Release Guide step B3):

    py -m PyInstaller --onedir --noconsole --name Makdi --icon makdi.ico app.py

Requires: pip install pywebview  (uses Edge WebView2 on Windows 10/11).
Keep this file next to makdi.py.
"""

import socket
import threading
from http.server import ThreadingHTTPServer

import webview  # pywebview

import makdi  # the crawler module (makdi.py in the same folder)

# Allow Excel / CSV / PDF exports to download from the app window.
# Without this, pywebview silently blocks file downloads.
try:
    webview.settings["ALLOW_DOWNLOADS"] = True
except Exception:
    pass  # very old pywebview versions: setting doesn't exist


def port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def start_server():
    server = ThreadingHTTPServer(("127.0.0.1", makdi.PORT), makdi.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    url = f"http://127.0.0.1:{makdi.PORT}"
    if port_free(makdi.PORT):
        start_server()
    # else: an instance is already running — just open a window onto it.

    webview.create_window(
        f"Makdi v{makdi.VERSION} — the free unlimited SEO crawler",
        url,
        width=1360,
        height=860,
        min_size=(900, 600),
    )
    webview.start()


if __name__ == "__main__":
    main()
