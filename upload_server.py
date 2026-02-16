#!/usr/bin/env python3
import os
import argparse
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

CHUNK = 1024 * 64  # 64KB

class UploadHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # endpoint simple para probar conectividad
        if self.path.startswith("/health"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"OK\n")
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path != "/upload":
            self.send_response(404)
            self.end_headers()
            return

        # Nombre del archivo: /upload?filename=sobre.bin
        qs = urllib.parse.parse_qs(parsed.query)
        filename = os.path.basename(qs.get("filename", ["upload.bin"])[0])
        save_dir = self.server.save_dir
        os.makedirs(save_dir, exist_ok=True)
        out_path = os.path.join(save_dir, filename)

        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            self.send_response(411)  # Length Required
            self.end_headers()
            return

        # Guardar el body crudo (octetos) tal cual llegan
        remaining = length
        with open(out_path, "wb") as f:
            while remaining > 0:
                chunk = self.rfile.read(min(CHUNK, remaining))
                if not chunk:
                    break
                f.write(chunk)
                remaining -= len(chunk)

        self.send_response(201)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(f"Saved: {out_path}\n".encode("utf-8"))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0", help="IP a la que se enlaza el servidor")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--dir", default="/tmp/inbox", help="Directorio destino")
    args = ap.parse_args()

    httpd = ThreadingHTTPServer((args.bind, args.port), UploadHandler)
    httpd.save_dir = args.dir
    print(f"Listening on http://{args.bind}:{args.port}  saving to {args.dir}")
    httpd.serve_forever()

if __name__ == "__main__":
    main()