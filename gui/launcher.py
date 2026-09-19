#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sqlmap GUI 一键启动(加强版)

- 自动选择空闲端口(避免 Address already in use)
- 监控 sqlmapapi 进程,死了自动拉起(守护)
- 任务数据持久化到 ~/.local/share/sqlmap-gui/tasks.json
- 即使 launcher 重启,运行中的任务可自动重新注册到新 sqlmapapi
"""

from __future__ import print_function

import argparse
import http.client
import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import base64
import secrets

ROOT = os.environ.get("SQLMAP_HOME") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUI_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(GUI_DIR, "web")

API_HOST = "127.0.0.1"
API_PORT = 8775
WEB_HOST = "127.0.0.1"
WEB_PORT = 8966

# 持久化目录
TASKS_STATE_FILE = os.path.expanduser("~/.local/share/sqlmap-gui/tasks.json")

api_proc = None
api_user = "admin"
api_pass = None
api_port = None
web_port = None

# 持久化状态:taskid -> {url, options, status, returncode, time}
persisted_tasks = {}
persisted_lock = threading.Lock()


def log(msg):
    print("[launcher] %s" % msg, flush=True)


def find_free_port(preferred):
    """如果首选端口被占,自动选一个空闲的。返回实际可用端口。"""
    for try_port in [preferred] + list(range(preferred + 1, preferred + 50)):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((API_HOST, try_port))
            got = s.getsockname()[1]
        finally:
            s.close()
        if got == try_port:
            return try_port
    raise RuntimeError("no free port near %d" % preferred)


def persist_tasks_load():
    global persisted_tasks
    try:
        with open(TASKS_STATE_FILE, "r") as f:
            persisted_tasks = json.load(f)
        log("已加载持久化任务: %d 个" % len(persisted_tasks))
    except FileNotFoundError:
        persisted_tasks = {}
    except Exception as e:
        log("持久化任务加载失败: %s" % e)
        persisted_tasks = {}


def persist_tasks_save():
    try:
        os.makedirs(os.path.dirname(TASKS_STATE_FILE), exist_ok=True)
        tmp = TASKS_STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(persisted_tasks, f, ensure_ascii=False, indent=2)
        os.replace(tmp, TASKS_STATE_FILE)
    except Exception as e:
        log("持久化任务保存失败: %s" % e)


def persist_task_record(taskid, url, options, status, returncode=None):
    with persisted_lock:
        persisted_tasks[taskid] = {
            "url": url,
            "options": options,
            "status": status,
            "returncode": returncode,
            "time": time.time(),
        }
        persist_tasks_save()


def persist_task_remove(taskid):
    with persisted_lock:
        if taskid in persisted_tasks:
            del persisted_tasks[taskid]
            persist_tasks_save()


def start_api(api_port_arg):
    global api_proc, api_pass, api_port
    api_pass = secrets.token_hex(12)
    api_script = os.path.join(ROOT, "sqlmapapi.py")
    if not os.path.isfile(api_script):
        log("ERROR: sqlmapapi.py not found at %s" % api_script)
        sys.exit(1)

    # 自动找空闲端口
    actual_port = find_free_port(api_port_arg)
    api_port = actual_port
    if actual_port != api_port_arg:
        log("api port %d 被占,自动改用 %d" % (api_port_arg, actual_port))

    cmd = [
        sys.executable, api_script,
        "-s",
        "--host", API_HOST,
        "--port", str(actual_port),
        "--username", api_user,
        "--password", api_pass,
    ]
    log("starting sqlmap API: %s" % " ".join(cmd))
    patch = os.path.join(GUI_DIR, "http_patch.py")
    env = dict(os.environ)
    if os.path.isfile(patch):
        customize = os.path.join(GUI_DIR, "usercustomize.py")
        try:
            import shutil
            shutil.copyfile(patch, customize)
        except Exception:
            pass
        env["PYTHONPATH"] = GUI_DIR + (os.pathsep + env["PYTHONPATH"]) if env.get("PYTHONPATH") else GUI_DIR
        log("applied local connection patch: %s" % patch)
    api_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)

    # 等就绪
    ready = False
    for _ in range(40):
        try:
            s = socket.create_connection((API_HOST, actual_port), timeout=1)
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

    log("sqlmap API ready at http://%s:%d (user=%s pass=%s)" % (API_HOST, actual_port, api_user, api_pass))
    _rehydrate_persisted_tasks(actual_port)


def _rehydrate_persisted_tasks(actual_port):
    """launcher 启动后,把持久化的扫描配置重新注册并启动到 sqlmapapi。
    注意:taskid 是 sqlmapapi 随机生成的,无法复用旧的,所以持久化的是 url+options。
    恢复后前端在下一次 /admin/list 拉取时能看到这些任务。"""
    if not persisted_tasks:
        return
    auth = "Basic %s" % base64.b64encode(("%s:%s" % (api_user, api_pass)).encode()).decode()
    rehydrated = 0
    for old_tid, info in list(persisted_tasks.items()):
        opts = dict(info.get("options") or {})
        if not opts.get("url"):
            persist_task_remove(old_tid)
            continue
        try:
            # 1. 创建新任务
            conn = http.client.HTTPConnection(API_HOST, actual_port, timeout=5)
            conn.request("GET", "/task/new", headers={"Authorization": auth, "Connection": "close"})
            r = conn.getresponse(); data = r.read(); conn.close()
            j = json.loads(data.decode())
            if not j.get("success"):
                continue
            new_tid = j["taskid"]
            # 2. 设置选项
            conn = http.client.HTTPConnection(API_HOST, actual_port, timeout=10)
            conn.request("POST", "/option/%s/set" % new_tid,
                         body=json.dumps(opts).encode(),
                         headers={"Authorization": auth, "Content-Type": "application/json", "Connection": "close"})
            r = conn.getresponse(); r.read(); conn.close()
            # 3. 启动扫描(如果之前是 running)
            if info.get("status") == "running":
                # 只在 url + url 后没有 GET 参数时给出 warning;有参数时启动
                conn = http.client.HTTPConnection(API_HOST, actual_port, timeout=5)
                conn.request("POST", "/scan/%s/start" % new_tid,
                             body=b'{"url": "%s"}' % opts["url"].encode(),
                             headers={"Authorization": auth, "Content-Type": "application/json", "Connection": "close"})
                r = conn.getresponse(); r.read(); conn.close()
                rehydrated += 1
                log("已重新注册并启动任务: %s -> %s (%s)" % (old_tid[:8], new_tid[:8], opts["url"][:50]))
            else:
                rehydrated += 1
                log("已重新注册任务(已结束): %s -> %s" % (old_tid[:8], new_tid[:8]))
            # 删除旧的(taskid 已变)
            persist_task_remove(old_tid)
        except Exception as e:
            log("持久化任务 %s 恢复失败: %s" % (old_tid[:8], e))
    if rehydrated:
        log("已完成持久化任务重新注册: %d 个" % rehydrated)


class ProxyHandler(http.server.SimpleHTTPRequestHandler):
    def api_base(self):
        return "http://%s:%d" % (API_HOST, api_port)

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=WEB_DIR, **kw)

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/api/"):
            return self.proxy("GET")
        if self.path == "/health":
            payload = json.dumps({
                "ok": True,
                "api_alive": api_proc is not None and api_proc.poll() is None,
                "api_port": api_port,
                "web_port": web_port,
                "persisted_tasks": len(persisted_tasks),
            }, ensure_ascii=False).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload); return
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
        if self.path == "/persist-task":
            return self.persist_task()
        if self.path.startswith("/api/"):
            return self.proxy("POST")
        self.send_error(405)

    def persist_task(self):
        """前端在创建/删除/任务完成时调用,记录到磁盘,用于 launcher 重启后恢复。"""
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        try: data = json.loads(body) if body else {}
        except Exception: data = {}
        taskid = data.get("taskid", "")
        action = data.get("action", "update")  # update | remove
        if not taskid:
            self._send_json(400, {"success": False, "message": "缺少 taskid"}); return
        if action == "remove":
            persist_task_remove(taskid)
            self._send_json(200, {"success": True, "message": "已从持久化移除"}); return
        url = data.get("url", "")
        options = data.get("options", {})
        status = data.get("status", "")
        returncode = data.get("returncode")
        persist_task_record(taskid, url, options, status, returncode)
        self._send_json(200, {"success": True, "message": "已持久化"})

    def proxy(self, method):
        rel = self.path[len("/api"):]
        parsed_path = urllib.parse.urlsplit(rel)
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else None
        auth = "Basic %s" % base64.b64encode(("%s:%s" % (api_user, api_pass)).encode()).decode()
        headers = {"Authorization": auth, "Connection": "close"}
        if body:
            headers["Content-Type"] = "application/json"

        last_err = None
        for attempt in range(3):
            conn = None
            try:
                conn = http.client.HTTPConnection(API_HOST, api_port, timeout=300)
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
        self.send_response(502); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)

    def save_request(self):
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

    def open_path(self):
        import subprocess
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        try: data = json.loads(body) if body else {}
        except Exception: data = {}
        path = data.get("path", "")
        if not path:
            self._send_json(400, {"success": False, "message": "缺少 path 参数"}); return
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            self._send_json(404, {"success": False, "message": "路径不存在: " + path}); return
        try:
            if sys.platform == "darwin": subprocess.Popen(["open", path])
            elif sys.platform.startswith("win"): subprocess.Popen(["explorer", path])
            else: subprocess.Popen(["xdg-open", path])
            self._send_json(200, {"success": True, "message": "已打开: " + path})
        except Exception as e:
            self._send_json(200, {"success": False, "message": "打开失败: " + str(e)})

    def purge_history(self):
        import shutil
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        try: data = json.loads(body) if body else {}
        except Exception: data = {}
        if data.get("confirm") != "YES":
            self._send_json(400, {"success": False, "message": "需要 confirm=YES 确认删除"}); return
        path = data.get("path", "")
        if not path: self._send_json(400, {"success": False, "message": "缺少 path 参数"}); return
        path = os.path.realpath(os.path.expanduser(path))
        base = os.path.realpath(os.path.expanduser("~/.local/share/sqlmap/output"))
        if not path.startswith(base + os.sep) and path != base:
            self._send_json(403, {"success": False, "message": "只能删除 sqlmap 输出目录下的内容"}); return
        if not os.path.isdir(path):
            self._send_json(404, {"success": False, "message": "目录不存在"}); return
        try:
            shutil.rmtree(path)
            self._send_json(200, {"success": True, "message": "已删除"})
        except Exception as e:
            self._send_json(200, {"success": False, "message": "删除失败: " + str(e)})

    def output_dir(self):
        path = os.path.expanduser("~/.local/share/sqlmap/output")
        targets = []
        try:
            if os.path.isdir(path):
                for name in sorted(os.listdir(path)):
                    full = os.path.join(path, name)
                    if not os.path.isdir(full): continue
                    st = os.stat(full); size = 0; fc = 0; has_sess = False; has_dump = False
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

    def _send_json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)


def _watchdog():
    """守护线程:监控 sqlmapapi 进程,死了自动拉起。"""
    global api_proc
    while True:
        time.sleep(3)
        if api_proc and api_proc.poll() is not None:
            log("sqlmap API 进程退出,自动重启...")
            try:
                # 不重置密码(假设 sqlmapapi 自己能重启),但要拉起
                api_script = os.path.join(ROOT, "sqlmapapi.py")
                patch = os.path.join(GUI_DIR, "http_patch.py")
                env = dict(os.environ)
                if os.path.isfile(patch):
                    customize = os.path.join(GUI_DIR, "usercustomize.py")
                    try:
                        import shutil
                        shutil.copyfile(patch, customize)
                    except: pass
                    env["PYTHONPATH"] = GUI_DIR + (os.pathsep + env["PYTHONPATH"]) if env.get("PYTHONPATH") else GUI_DIR
                cmd = [sys.executable, api_script, "-s", "--host", API_HOST,
                       "--port", str(api_port), "--username", api_user, "--password", api_pass]
                api_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
                log("sqlmap API 重启完成")
                _rehydrate_persisted_tasks(api_port)
            except Exception as e:
                log("重启失败: %s" % e)


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
    global API_HOST, WEB_HOST, api_port, web_port
    import secrets
    ap = argparse.ArgumentParser(description="sqlmap GUI launcher (增强版)")
    ap.add_argument("--api-port", type=int, default=API_PORT)
    ap.add_argument("--web-port", type=int, default=WEB_PORT)
    ap.add_argument("--api-host", default=API_HOST)
    ap.add_argument("--web-host", default=WEB_HOST)
    args = ap.parse_args()

    API_HOST = args.api_host
    WEB_HOST = args.web_host

    # web 端口也找空闲
    actual_web_port = find_free_port(args.web_port)
    web_port = actual_web_port
    if actual_web_port != args.web_port:
        log("web port %d 被占,自动改用 %d" % (args.web_port, actual_web_port))

    # 先加载持久化任务
    persist_tasks_load()

    # 启动 sqlmapapi(里面会自动找空闲端口)
    start_api(args.api_port)

    # 启动守护线程
    threading.Thread(target=_watchdog, daemon=True).start()

    httpd = http.server.ThreadingHTTPServer((args.web_host, actual_web_port), ProxyHandler)
    log("GUI ready at http://%s:%d  (Ctrl-C to stop)" % (args.web_host, actual_web_port))
    print("")
    print("  +---------------------------------------------------+")
    print("  |  sqlmap GUI  —  open in your browser:              |")
    print("  |  http://%s:%d  |" % (args.web_host, actual_web_port))
    print("  +---------------------------------------------------+")
    print("")
    print("  特性:端口冲突自动避让 / sqlmapapi 自动守护重启 / 任务数据持久化")
    print("  健康检查: http://%s:%d/health" % (args.web_host, actual_web_port))
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
