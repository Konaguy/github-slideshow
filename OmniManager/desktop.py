"""
OmniManager Desktop Entry Point
Boots Flask in a background thread, then opens a native pywebview window.
Works on Mac (WKWebView) and Windows (Edge WebView2).
"""
import os
import sys
import socket
import threading
import time

# ── PyInstaller bundle path fix ────────────────────────────────────────────────
if getattr(sys, "frozen", False):
    # Running inside a PyInstaller bundle
    _base = sys._MEIPASS
    os.chdir(_base)
    sys.path.insert(0, _base)

# Load .env if present (dev mode)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_server(port: int, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def start_flask(port: int) -> None:
    os.environ.setdefault("FLASK_ENV", "production")
    os.environ["PORT"] = str(port)
    from app import create_app
    from app.extensions import socketio
    app = create_app("production")
    socketio.run(app, host="127.0.0.1", port=port, use_reloader=False, log_output=False)


# ── Loading page (shown while Flask warms up) ──────────────────────────────────

_LOADING_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: linear-gradient(135deg, #1a0a4a 0%, #2d1269 50%, #1a0a4a 100%);
    display: flex; align-items: center; justify-content: center;
    height: 100vh; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  }
  .wrap { text-align: center; color: white; }
  .logo { font-size: 3.5rem; margin-bottom: 1rem; }
  .title { font-size: 1.8rem; font-weight: 700; letter-spacing: -0.02em; }
  .sub { color: rgba(255,255,255,0.45); margin-top: 0.5rem; font-size: 0.9rem; }
  .dots { display: flex; gap: 6px; justify-content: center; margin-top: 2rem; }
  .dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: #c040d0;
    animation: pulse 1.2s ease-in-out infinite;
  }
  .dot:nth-child(2) { animation-delay: 0.2s; }
  .dot:nth-child(3) { animation-delay: 0.4s; }
  @keyframes pulse {
    0%, 80%, 100% { opacity: 0.2; transform: scale(0.8); }
    40% { opacity: 1; transform: scale(1); }
  }
</style>
</head>
<body>
  <div class="wrap">
    <div class="logo">⚡</div>
    <div class="title">OmniManager</div>
    <div class="sub">Starting up…</div>
    <div class="dots">
      <div class="dot"></div>
      <div class="dot"></div>
      <div class="dot"></div>
    </div>
  </div>
</body>
</html>
"""


# ── pywebview startup callback ─────────────────────────────────────────────────

def _on_start(window, port: int) -> None:
    """Called by pywebview after the window is created. Navigate once Flask is up."""
    if wait_for_server(port):
        window.load_url(f"http://127.0.0.1:{port}")
    else:
        window.load_html("<h1 style='color:red;font-family:sans-serif;padding:2rem'>Flask failed to start.</h1>")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    import webview

    port = find_free_port()

    flask_thread = threading.Thread(target=start_flask, args=(port,), daemon=True)
    flask_thread.start()

    window = webview.create_window(
        title="OmniManager",
        html=_LOADING_HTML,
        width=1280,
        height=820,
        min_size=(960, 640),
        background_color="#1a0a4a",
        text_select=False,
    )

    # Use Edge WebView2 on Windows, default (WKWebView) on Mac
    gui_backend = "edgechromium" if sys.platform == "win32" else None
    webview.start(_on_start, args=[window, port], gui=gui_backend)


if __name__ == "__main__":
    main()
