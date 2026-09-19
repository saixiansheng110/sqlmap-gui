# -*- coding: utf-8 -*-
"""
sqlmap 本机连接补丁。

问题:sqlmap 的 lib/request/connect.py 最终调用 urllib.request.urlopen() 发送请求。
在 macOS 上,urllib 对某些本地 HTTP 服务(如 Tomcat/sqli-labs)会得到
RemoteDisconnected("Remote end closed connection without response"),
而 http.client 能正常通信。

本补丁把 urllib.request.urlopen 替换为基于 http.client 的实现,
仅作用于 sqlmapapi 子进程,不修改 sqlmap 源码,不影响系统 Python。

通过 launcher 的 PYTHONSTARTUP 环境变量注入。
"""

import io
import http.client
import urllib.request
import urllib.error

_orig_urlopen = urllib.request.urlopen


class _HTTPResponseWrapper:
    """把 http.client 的响应对象包装成 urllib 响应对象的样子(urllib.request.urlopen 的返回值)。"""

    def __init__(self, resp, body, url, headers, status):
        self._resp = resp
        self._body = body
        self.url = url
        self.headers = headers
        self.status = status
        self.code = status
        self.msg = resp.reason or ""

    def read(self, amt=None):
        if amt is None:
            return self._body
        return self._body[:amt]

    def geturl(self):
        return self.url

    def getcode(self):
        return self.status

    def info(self):
        return self.headers

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def __iter__(self):
        return iter(self._body.split(b"\n"))


def _patched_urlopen(req, timeout=None, *args, **kwargs):
    """用 http.client 实现的 urlopen,绕开 urllib 在本机连接的问题。"""
    url = req.full_url if hasattr(req, "full_url") else str(req)
    # 解析 URL
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    host = parts.hostname or "127.0.0.1"
    port = parts.port
    scheme = parts.scheme or "http"
    if port is None:
        port = 443 if scheme == "https" else 80
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    method = req.get_method() if hasattr(req, "get_method") else "GET"
    headers = dict(req.header_items()) if hasattr(req, "header_items") else {}
    data = req.data if hasattr(req, "data") and req.data else None
    if data and isinstance(data, str):
        data = data.encode("utf-8")

    conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(host, port, timeout=timeout or 30)
    try:
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        return _HTTPResponseWrapper(resp, body, url, resp.msg, resp.status)
    except http.client.HTTPException as e:
        raise urllib.error.URLError(str(e))
    finally:
        # 让连接对象在响应读取后关闭;调用方只读 body
        pass


def _apply():
    """替换 urllib.request.urlopen。仅在能成功导入 urllib 时生效。"""
    try:
        urllib.request.urlopen = _patched_urlopen
    except Exception:
        pass


_apply()
