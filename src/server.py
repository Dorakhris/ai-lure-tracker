"""
AI Lure Tracker - Local Web Dashboard Server
Serves the web UI and live threat feeds on http://localhost:8000.
"""

import http.server
import socketserver
import os
import sys
import webbrowser
import logging

logger = logging.getLogger("ai_lure_tracker.server")


class DualDirectoryHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        # Route feeds/ requests to the feeds directory
        clean_path = path.split("?")[0]
        if clean_path.startswith("/feeds/"):
            rel_path = clean_path.replace("/feeds/", "", 1)
            return os.path.abspath(os.path.join("feeds", rel_path))

        # Route reports/ requests to the reports directory
        if clean_path.startswith("/reports/"):
            rel_path = clean_path.replace("/reports/", "", 1)
            return os.path.abspath(os.path.join("reports", rel_path))

        # Default route to web/ directory
        if clean_path == "/" or clean_path == "":
            return os.path.abspath(os.path.join("web", "index.html"))

        return os.path.abspath(os.path.join("web", clean_path.lstrip("/")))

    def end_headers(self):
        # Enable CORS for local testing
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()


def start_server(port: int = 8000, open_browser: bool = False):
    handler = DualDirectoryHTTPHandler
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"\n[+] AI Lure Tracker Web Portal live at: http://localhost:{port}")
        print(f"[+] Press Ctrl+C to stop the server.\n")
        if open_browser:
            webbrowser.open(f"http://localhost:{port}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down web server...")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    start_server(port)
