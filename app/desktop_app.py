# app/desktop_app.py

"""
VAJRA Native Desktop App -- one-click chatbot-style launcher.

Runs the existing FastAPI backend (app.api:app) in a background thread
and opens the shared CHAT_HTML frontend (app/dashboard/chat_ui.py) in a
real native window via pywebview. No browser tab, no manual server start,
no typed URLs -- just a single app window.

Also exposes native file/folder picker dialogs to the page via pywebview's
js_api bridge (window.pywebview.api), so choosing a ZIP or a project folder
uses the real OS picker instead of an HTML <input type="file">, which is
known to be unreliable inside some embedded WebView2 hosts.
"""

import socket
import threading
import time

import uvicorn
import webview

HOST = "127.0.0.1"


class Api:
    """Methods exposed to the page as window.pywebview.api.<name>()."""

    def pick_zip_file(self):
        result = webview.windows[0].create_file_dialog(
            webview.OPEN_DIALOG,
            file_types=("ZIP archives (*.zip)", "All files (*.*)"),
        )
        if not result:
            return None
        return result[0]

    def pick_folder(self):
        result = webview.windows[0].create_file_dialog(webview.FOLDER_DIALOG)
        if not result:
            return None
        return result[0]


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def _run_server(port: int):
    from app.api import app as fastapi_app

    config = uvicorn.Config(fastapi_app, host=HOST, port=port, log_level="warning")
    server = uvicorn.Server(config)
    server.run()


def _wait_for_server(port: int, timeout: float = 15.0):
    import urllib.request

    deadline = time.time() + timeout
    url = f"http://{HOST}:{port}/health"
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=0.5)
            return True
        except Exception:
            time.sleep(0.2)
    return False


def main():
    port = _find_free_port()
    print(f"[VAJRA] Starting backend on http://{HOST}:{port}")

    server_thread = threading.Thread(target=_run_server, args=(port,), daemon=True)
    server_thread.start()

    if not _wait_for_server(port):
        raise RuntimeError("VAJRA backend did not start in time.")
    print("[VAJRA] Backend is up, opening window...")

    webview.create_window(
        "VAJRA",
        url=f"http://{HOST}:{port}/chat",
        width=1280,
        height=820,
        min_size=(960, 640),
        js_api=Api(),
    )
    # Force the modern Chromium engine (WebView2 on Windows). Without this,
    # pywebview can silently fall back to the old IE/MSHTML engine, which
    # can't run the fetch/async JS the chat UI depends on.
    # debug=True opens DevTools (right-click -> Inspect) so JS console
    # errors are visible instead of failing silently -- turn this off once
    # things are stable if you don't want the DevTools option available.
    webview.start(gui="edgechromium", debug=True)


if __name__ == "__main__":
    main()