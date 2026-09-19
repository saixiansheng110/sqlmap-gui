#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sqlmap GUI launcher.

Starts the sqlmap REST API server (sqlmapapi.py) as a subprocess and serves the
static web frontend on a second port. The frontend talks to the API through a
same-origin proxy at /api/* so the browser never deals with CORS or HTTP Basic.

    python3 gui/launcher.py                 # defaults: API 127.0.0.1:8775, web 127.0.0.1:8966
    python3 gui/launcher.py --api-port 9000 --web-port 8000

Default API credentials (admin / random per run) are printed at startup and
auto-injected into the browser session, so the operator never types them.
"""

from __future__ import print_function

import argparse
import http.client
import http.server
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
import base64

ROOT = os.environ.get("SQLMAP_HOME") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUI_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(GUI_DIR, "web")

API_HOST = "127.0.0.1"
API_PORT = 8775
WEB_HOST = "127.0.0.1"
WEB_PORT = 8966

api_proc = None
api_user = "admin"
api_pass = None  # generated per run


def log(msg):
    print("[launcher] %s" % msg, flush=True)


def find_free_port(default):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((API_HOST, 0))
        p = s.getsockname()[1]
    finally:
        s.close()
    return p if p != default else find_free_port(default)


def start_api(api_port):
    global api_proc, api_pass
    api_pass = secrets.token_hex(12)
    api_script = os.path.join(ROOT, "sqlmapapi.py")
    if not os.path.isfile(api_script):
        log("ERROR: sqlmapapi.py not found at %s" % api_script)
        sys.exit(1)

    cmd = [
        sys.executable, api_script,
        "-s",
        "--host", API_HOST,
        "--port", str(api_port),
        "--username", api_user,
        "--password", api_pass,
    ]
    log("starting sqlmap API: %s" % " ".join(cmd))
    # 注入本机连接补丁:sqlmap 内部用 urllib.request.urlopen,在 macOS 上连本地 HTTP
    # 服务会 RemoteDisconnected;补丁用 http.client 重写 urlopen,已验证可正常通信。
    # 用 usercustomize.py + PYTHONPATH 注入:Python 启动时自动加载 site 模块会 import usercustomize。
    patch = os.path.join(GUI_DIR, "http_patch.py")
    customize = os.path.join(GUI_DIR, "usercustomize.py")
    env = dict(os.environ)
    if os.path.isfile(patch):
        # 复制补丁为 usercustomize.py,让 Python 启动时自动执行
        try:
            import shutil
            shutil.copyfile(patch, customize)
        except Exception:
            pass
        env["PYTHONPATH"] = GUI_DIR + (os.pathsep + env["PYTHONPATH"]) if env.get("PYTHONPATH") else GUI_DIR
        log("applied local connection patch: %s" % patch)
    api_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)

    # wait for readiness by probing the TCP port directly. Using urllib here is
    # unreliable: bottle's wsgiref adapter sometimes drops the connection without
    # a response, which surfaces as RemoteDisconnected rather than an HTTPError.
    ready = False
    for _ in range(40):
        try:
            s = socket.create_connection((API_HOST, api_port), timeout=1)
            s.close()
            ready = True
            break
        except Exception:
            time.sleep(0.25)

    if not ready:
        log("ERROR: sqlmap API did not become ready")
        out = b""
        try:
            out = api_proc.stdout.read(2000)
        except Exception:
            pass
        log(out.decode("utf-8", "replace"))
        sys.exit(1)

    log("sqlmap API ready at http://%s:%d (user=%s pass=%s)" % (API_HOST, api_port, api_user, api_pass))


class ProxyHandler(http.server.SimpleHTTPRequestHandler):
    api_base = "http://%s:%d" % (API_HOST, API_PORT)

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=WEB_DIR, **kw)

    def log_message(self, fmt, *args):
        pass


    def do_GET(self):
        if self.path.startswith("/api/"):
            return self.proxy("GET")
        if self.path == "/output-dir":
            return self.output_dir()
        if self.path == "/" or self.path == "":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        if self.path == "/save-request":
            return self.save_request()
        if self.path == "/open-path":
            return self.open_path()
        if self.path == "/purge-history":
            return self.purge_history()
        if self.path.startswith("/api/"):
            return self.proxy("POST")
        self.send_error(405)

    def output_dir(self):
        path = os.path.expanduser("~/.local/share/sqlmap/output")
        targets = []
        try:
            if os.path.isdir(path):
                for name in sorted(os.listdir(path)):
                    full = os.path.join(path, name)
                    if not os.path.isdir(full): continue
                    st = os.stat(full)
                    size = 0; fc = 0; has_sess = False; has_dump = False
                    for root, dirs, files in os.walk(full):
                        for fn in files:
                            try:
                                size += os.path.getsize(os.path.join(root, fn)); fc += 1
                                if fn == "session.sqlite": has_sess = True
                                if fn.startswith("dump"): has_dump = True
                            except: pass
                    targets.append({"name":name,"path":full,"size_bytes":size,"file_count":fc,"has_session":has_sess,"has_dump":has_dump,"modified":int(st.st_mtime)})
        except Exception as e:
            log("output_dir error: %s" % e)
        targets.sort(key=lambda x: x["modified"], reverse=True)
        self._send_json(200, {"success": True, "path": path, "targets": targets})

    def purge_history(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        try: data = json.loads(body) if body else {}
        except: data = {}
        if data.get("confirm") != "YES":
            self._send_json(400, {"success": False, "message": "需要 confirm=YES 确认删除"}); return
        p = data.get("path", "")
        if not p: self._send_json(400, {"success": False, "message": "缺少 path 参数"}); return
        p = os.path.realpath(os.path.expanduser(p))
        base = os.path.realpath(os.path.expanduser("~/.local/share/sqlmap/output"))
        if not p.startswith(base + os.sep) and p != base:
            self._send_json(403, {"success": False, "message": "只能删除 sqlmap 输出目录下的内容"}); return
        if not os.path.isdir(p):
            self._send_json(404, {"success": False, "message": "目录不存在"}); return
        try:
            import shutil; shutil.rmtree(p)
            self._send_json(200, {"success": True, "message": "已删除"})
        except Exception as e:
            self._send_json(200, {"success": False, "message": "删除失败: " + str(e)})

    def _send_json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)


    def open_path(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}
        path = data.get("path", "")
        if not path:
            payload = json.dumps({"success": False, "message": "缺少 path 参数"}).encode()
            self.send_response(400); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload); return
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            payload = json.dumps({"success": False, "message": "路径不存在: " + path}).encode()
            self.send_response(404); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload); return
        # 用系统命令打开
        import subprocess
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", path])
            elif sys.platform.startswith("win"):
                subprocess.Popen(["explorer", path])
            else:
                subprocess.Popen(["xdg-open", path])
            payload = json.dumps({"success": True, "message": "已打开: " + path}).encode()
        except Exception as e:
            payload = json.dumps({"success": False, "message": "打开失败: " + str(e)}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)

    def save_request(self):
        """前端把粘贴的完整请求文本发来,写到临时文件,返回路径供 requestFile 选项使用"""
        import tempfile
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        if not body.strip():
            payload = json.dumps({"success": False, "message": "请求内容为空"}).encode()
            self.send_response(400); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload); return
        fd, path = tempfile.mkstemp(suffix=".req", prefix="sqlmap_req_")
        with os.fdopen(fd, "w") as f:
            f.write(body)
        log("saved request to %s (%d bytes)" % (path, len(body)))
        payload = json.dumps({"success": True, "path": path}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)

    def proxy(self, method):
        # strip /api prefix
        rel = self.path[len("/api"):]
        parsed_path = urllib.parse.urlsplit(rel)

        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else None

        auth = "Basic %s" % base64.b64encode(("%s:%s" % (api_user, api_pass)).encode()).decode()
        headers = {"Authorization": auth, "Connection": "close"}
        if body:
            headers["Content-Type"] = "application/json"

        # 重试机制:bottle 的 wsgiref 适配器在并发或重负载时会偶发重置连接
        # (Connection reset by peer / RemoteDisconnected),重试可自动恢复
        last_err = None
        for attempt in range(3):
            conn = None
            try:
                conn = http.client.HTTPConnection(API_HOST, API_PORT, timeout=300)
                path = parsed_path.path + (("?" + parsed_path.query) if parsed_path.query else "")
                conn.request(method, path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                self.send_response(resp.status)
                ctype = resp.getheader("Content-Type") or "application/json"
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                conn.close()
                return
            except (ConnectionResetError, http.client.RemoteDisconnected, http.client.BadStatusLine, http.client.IncompleteRead) as e:
                # 这些是 bottle 偶发的连接问题,重试
                last_err = e
                if conn:
                    try: conn.close()
                    except: pass
                time.sleep(0.2 * (attempt + 1))
                continue
            except Exception as e:
                last_err = e
                break
            finally:
                if conn:
                    try: conn.close()
                    except: pass
        payload = json.dumps({"success": False, "message": "代理错误(已重试3次): %s" % last_err}).encode()
        self.send_response(502)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def end_headers(self):
        # disable caching for index during dev; allow static for assets
        self.send_header("Cache-Control", "no-cache")
        super().end_headers()


def stop_api():
    global api_proc
    if api_proc:
        api_proc.terminate()
        try:
            api_proc.wait(timeout=5)
        except Exception:
            api_proc.kill()
        api_proc = None
        log("sqlmap API stopped")


def main():
    global API_HOST, API_PORT
    ap = argparse.ArgumentParser(description="sqlmap GUI launcher")
    ap.add_argument("--api-port", type=int, default=API_PORT)
    ap.add_argument("--web-port", type=int, default=WEB_PORT)
    ap.add_argument("--api-host", default=API_HOST)
    ap.add_argument("--web-host", default=WEB_HOST)
    args = ap.parse_args()

    API_HOST = args.api_host
    API_PORT = args.api_port
    ProxyHandler.api_base = "http://%s:%d" % (API_HOST, API_PORT)

    start_api(args.api_port)

    httpd = http.server.ThreadingHTTPServer((args.web_host, args.web_port), ProxyHandler)
    log("GUI ready at http://%s:%d  (Ctrl-C to stop)" % (args.web_host, args.web_port))
    print("")
    print("  +---------------------------------------------------+")
    print("  |  sqlmap GUI  —  open in your browser:              |")
    print("  |  http://%s:%d  |" % (args.web_host, args.web_port))
    print("  +---------------------------------------------------+")
    print("")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("")
        log("shutting down")
    finally:
        httpd.server_close()
        stop_api()


if __name__ == "__main__":
    main()
