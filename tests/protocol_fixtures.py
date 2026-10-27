"""本地协议夹具：动态 CA 的 TLS/HTTP1.1、真实 ALPN 的 HTTP/2、最小 RFC6455 WebSocket。

被 ``test_protocols.py`` 独占使用（其它套件不 import 本模块）。三条硬性约定：

* **只绑 127.0.0.1 + 端口 0**（内核分配），不连外网、不碰第三方站点；
* 每个夹具都有 ``stop()``：接受循环靠短超时轮询停止标志，活动连接在 ``stop()``
  里一并关闭，线程都设 daemon，避免套件退出时留悬空线程；
* 证书由 ``cryptography`` 现场生成到临时目录（本地好 CA、一个无亲缘的"错误 CA"、
  以及一个 SAN 不匹配的叶子证书），只用于本机校验路径，不写入仓库。

WebSocket 服务端刻意**不用** ``websockets`` 库，而是按 RFC6455 自己收发帧：
只有这样才观测得到客户端发来的 PING / 回给我们的 PONG / CLOSE 的方向与载荷，
用现成库的话这些控制帧会被库内部消化掉，"ping/pong 回归"就只剩一句空话。
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import importlib.metadata
import ipaddress
import json
import shutil
import socket
import ssl
import struct
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

__all__ = [
    "HOST", "LOCALHOST", "WS_CMD_CLOSE", "WS_CMD_PING", "WS_PING_PROBE", "WS_PONG_OK",
    "OP_CONT", "OP_TEXT", "OP_BINARY", "OP_CLOSE", "OP_PING", "OP_PONG",
    "CertBundle", "H2Server", "TLSHttpServer", "WebSocketServer",
    "deps_report", "port_open",
]

HOST = "127.0.0.1"
LOCALHOST = "localhost"
_WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# WebSocket opcode
OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA
OP_ = {"cont": OP_CONT, "text": OP_TEXT, "binary": OP_BINARY,
       "close": OP_CLOSE, "ping": OP_PING, "pong": OP_PONG}

# 服务端约定指令（客户端发的文本帧）
WS_CMD_PING = "ping-please"      # -> 服务端回 PING(b"probe")，客户端应自动回 PONG
WS_CMD_CLOSE = "close-me"        # -> 服务端主动发 CLOSE(1000)
WS_PING_PROBE = b"probe"
WS_PONG_OK = "pong-ok"           # 服务端确认收到客户端 PONG 后回的数据帧

# --------------------------------------------------------------------------- #
# 依赖探测：缺依赖必须能被明确报告（调用方据此记 blocked + 非零退出）
# --------------------------------------------------------------------------- #
try:
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.x509.oid import ExtendedKeyUsageOID as _EKU
    from cryptography.x509.oid import NameOID as _NAMEOID

    _CRYPTO_ERROR = None
except Exception as _exc:  # noqa: BLE001
    _CRYPTO_ERROR = "%s: %s" % (type(_exc).__name__, _exc)

try:
    import h2.connection as _h2_conn
    import h2.events as _h2_events

    _H2_ERROR = None
except Exception as _exc:  # noqa: BLE001
    _H2_ERROR = "%s: %s" % (type(_exc).__name__, _exc)


def _h2_new_server_connection():
    """构造一个**服务端** h2 连接（夹具 bug 修复点）。

    h2 >= 4.4 把 ``client_side`` 从 ``H2Connection()`` 挪进了 ``H2Configuration``：
    现在 ``H2Connection()`` 默认是**客户端**连接。夹具原来直接 ``H2Connection()``
    当服务端用，于是接手的第一件事就是把客户端 preface
    （``PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n``）当成自己的首帧发出去 —— 真实
    客户端（nghttp2）看到服务端发 preface 会直接报 ``CURLE_HTTP2`` framing error，
    而假服务端也永远解析不出 ``RequestReceived``。这里显式声明服务端角色，
    同时兼容老版本 h2 的关键字写法。
    """
    try:
        from h2.config import H2Configuration as _H2Config
    except Exception:  # noqa: BLE001 - 老版本/裁剪安装时退回默认
        return _h2_conn.H2Connection()
    try:
        # normalize_inbound_headers=False：h2 库默认会把收到的所有 ``cookie`` 字段
        # 合并成一条、并挪到 header 块**末尾**（utilities._combine_cookie_fields，
        # 这是 RFC 7540 §8.1.2.5 接收端的正规化）。夹具要看的正是"客户端到底发了几条、
        # 按什么顺序"，被它整理过就什么都看不出来了，所以这里必须关掉。
        return _h2_conn.H2Connection(
            config=_H2Config(client_side=False, normalize_inbound_headers=False))
    except TypeError:  # h2 < 4.4：client_side 还是 H2Connection 的参数
        return _h2_conn.H2Connection(client_side=False)


def _pkg_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except Exception:  # noqa: BLE001
        return "<unknown>"


def deps_report() -> dict:
    """本模块真正用到的第三方依赖状态（websockets 明确标注为不使用）。"""
    return {
        "cryptography": {
            "needed_for": "本地 CA / 叶子证书生成",
            "used": True,
            "ok": _CRYPTO_ERROR is None,
            "version": None if _CRYPTO_ERROR else _pkg_version("cryptography"),
            "error": _CRYPTO_ERROR,
        },
        "h2": {
            "needed_for": "真实 ALPN h2 服务端（自己实现 HTTP/2 帧不现实）",
            "used": True,
            "ok": _H2_ERROR is None,
            "version": None if _H2_ERROR else _pkg_version("h2"),
            "error": _H2_ERROR,
        },
        "websockets": {
            "needed_for": "无 —— WS 服务端按 RFC6455 自实现，以便观测 PING/PONG/CLOSE",
            "used": False,
            "ok": True,
            "version": _pkg_version("websockets"),
            "error": None,
        },
    }


def port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    """端口是否还能连上（用来断言 stop() 真的把监听关掉了）。"""
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# 本地 PKI
# --------------------------------------------------------------------------- #
def _pem_cert(cert) -> bytes:
    return cert.public_bytes(_ser.Encoding.PEM)


def _pem_key(key) -> bytes:
    return key.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8,
                             _ser.NoEncryption())


def _ca(name: str):
    key = _ec.generate_private_key(_ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (_x509.CertificateBuilder()
            .subject_name(_x509.Name([_x509.NameAttribute(_NAMEOID.COMMON_NAME, name)]))
            .issuer_name(_x509.Name([_x509.NameAttribute(_NAMEOID.COMMON_NAME, name)]))
            .public_key(key.public_key())
            .serial_number(_x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=10))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(_x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(_x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, _hashes.SHA256()))
    return key, cert


def _leaf(ca_key, ca_cert, cn: str, dns: list, ips: list):
    key = _ec.generate_private_key(_ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    san = _x509.SubjectAlternativeName(
        [_x509.DNSName(d) for d in dns] + [_x509.IPAddress(ipaddress.ip_address(i)) for i in ips])
    cert = (_x509.CertificateBuilder()
            .subject_name(_x509.Name([_x509.NameAttribute(_NAMEOID.COMMON_NAME, cn)]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(_x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=10))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(san, critical=False)
            .add_extension(_x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_x509.ExtendedKeyUsage([_EKU.SERVER_AUTH]), critical=False)
            .add_extension(_x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=False)
            .sign(ca_key, _hashes.SHA256()))
    return key, cert


class CertBundle:
    """一次运行用的本地 PKI 材料（好 CA + 错误 CA + SAN 不匹配的叶子证书）。"""

    def __init__(self, directory: Path, **paths) -> None:
        self.dir = directory
        self.ca_path = paths["ca_path"]                    # 受信任的本地 CA（PEM 文件）
        self.rogue_ca_path = paths["rogue_ca_path"]        # 与服务器证书无亲缘的 CA
        self.cert_path = paths["cert_path"]                # SAN: localhost + 127.0.0.1
        self.key_path = paths["key_path"]
        self.badname_cert_path = paths["badname_cert_path"]  # SAN: wrong.example（同属好 CA）
        self.badname_key_path = paths["badname_key_path"]
        self.info = paths["info"]

    @classmethod
    def create(cls, base_dir: str | None = None) -> "CertBundle":
        if _CRYPTO_ERROR is not None:
            raise RuntimeError("cryptography 不可用：%s" % _CRYPTO_ERROR)
        d = Path(tempfile.mkdtemp(prefix="nb-curl-proto-pki-", dir=base_dir))

        def w(name: str, data: bytes) -> Path:
            p = d / name
            p.write_bytes(data)
            return p

        good_key, good_ca = _ca("nb-curl local test CA")
        rogue_key, rogue_ca = _ca("nb-curl rogue CA (must not be trusted)")
        leaf_key, leaf = _leaf(good_key, good_ca, LOCALHOST, [LOCALHOST], [HOST])
        bad_key, bad = _leaf(good_key, good_ca, "wrong.example", ["wrong.example"], [])

        info = {
            "dir": str(d),
            "ca_sha256": hashlib.sha256(_pem_cert(good_ca)).hexdigest(),
            "rogue_ca_sha256": hashlib.sha256(_pem_cert(rogue_ca)).hexdigest(),
            "server_cert_sha256": hashlib.sha256(_pem_cert(leaf)).hexdigest(),
            "server_san": [LOCALHOST, HOST],
            "badname_san": ["wrong.example"],
            "server_cert_issuer": leaf.issuer.rfc4514_string(),
        }
        return cls(d, ca_path=w("ca.pem", _pem_cert(good_ca)),
                   rogue_ca_path=w("rogue-ca.pem", _pem_cert(rogue_ca)),
                   cert_path=w("server.pem", _pem_cert(leaf)),
                   key_path=w("server.key", _pem_key(leaf_key)),
                   badname_cert_path=w("badname.pem", _pem_cert(bad)),
                   badname_key_path=w("badname.key", _pem_key(bad_key)),
                   info=info)

    def cleanup(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def describe(self) -> dict:
        return dict(self.info)


# --------------------------------------------------------------------------- #
# TLS + HTTP/1.1
# --------------------------------------------------------------------------- #
class _H1Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nb-curl-local-h1"
    sys_version = ""

    def log_message(self, *args) -> None:  # 静音
        pass

    def setup(self) -> None:
        super().setup()
        self.server.owner.note_connection(self.connection)  # 每个 TCP 连接一次

    def _respond(self) -> None:
        self.server.owner.note_request(self.path)
        body = json.dumps({"server": "h1", "path": self.path,
                           "protocol": self.protocol_version}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _respond


class _TLSThreadingServer(ThreadingHTTPServer):
    """监听 socket 保持明文，TLS 在每次 accept 后包装（握手失败只丢那条连接）。"""

    daemon_threads = True
    ssl_context = None

    def get_request(self):
        sock, addr = super().get_request()
        return self.ssl_context.wrap_socket(sock, server_side=True), addr


class TLSHttpServer:
    """TLS 上的 HTTP/1.1 服务（证书由调用方给），记录 ALPN / TLS 版本 / 连接数。"""

    def __init__(self, certfile, keyfile, alpn=("http/1.1",), host: str = HOST) -> None:
        self._lock = threading.Lock()
        self.connections = 0
        self.requests = 0
        self.alpn_seen: list = []
        self.tls_seen: list = []
        self.ciphers: list = []

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(certfile), str(keyfile))
        ctx.set_alpn_protocols(list(alpn))

        self._httpd = _TLSThreadingServer((host, 0), _H1Handler)
        self._httpd.owner = self
        self._httpd.ssl_context = ctx
        self.host, self.port = self._httpd.socket.getsockname()[:2]
        self._thread = None
        self._started = False

    def note_connection(self, conn) -> None:
        try:
            alpn = conn.selected_alpn_protocol()
            ver = conn.version()
            cipher = conn.cipher()[0] if conn.cipher() else None
        except Exception as exc:  # noqa: BLE001
            alpn, ver, cipher = None, "error: %r" % (exc,), None
        with self._lock:
            self.connections += 1
            self.alpn_seen.append(alpn)
            self.tls_seen.append(ver)
            self.ciphers.append(cipher)

    def note_request(self, path: str) -> None:
        with self._lock:
            self.requests += 1

    def url(self, path: str = "/", hostname: str = LOCALHOST) -> str:
        return "https://%s:%d%s" % (hostname, self.port, path)

    def start(self) -> "TLSHttpServer":
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        kwargs={"poll_interval": 0.2}, daemon=True)
        self._thread.start()
        self._started = True
        return self

    def stop(self) -> None:
        if not self._started:      # 没 start 过就别调 shutdown（会一直等）
            return
        self._started = False
        try:
            self._httpd.shutdown()
        except Exception:  # noqa: BLE001
            pass
        try:
            self._httpd.server_close()
        except Exception:  # noqa: BLE001
            pass
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def describe(self) -> dict:
        with self._lock:
            return {"url": "https://%s:%d" % (LOCALHOST, self.port), "port": self.port,
                    "protocol": "HTTP/1.1", "alpn": self.alpn_seen,
                    "tls": self.tls_seen, "cipher": self.ciphers}


# --------------------------------------------------------------------------- #
# TLS + 真实 ALPN 协商的 HTTP/2（保持连接、并发多 stream、连接计数）
# --------------------------------------------------------------------------- #
_H2_CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _h2_scan_frames(data: bytes) -> list:
    """把客户端明文（preface + 帧）切成帧；尾部不完整的帧直接丢掉。

    只做 HTTP/2 通用帧头解析（RFC 9113 §4.1），不关心 HPACK 内容。
    """
    out: list = []
    i = len(_H2_CLIENT_PREFACE) if data.startswith(_H2_CLIENT_PREFACE) else 0
    while i + 9 <= len(data):
        length = int.from_bytes(data[i:i + 3], "big")
        ftype = data[i + 3]
        flags = data[i + 4]
        stream = int.from_bytes(data[i + 5:i + 9], "big") & 0x7FFFFFFF
        payload = data[i + 9:i + 9 + length]
        if len(payload) < length:
            break                      # 帧还没收全
        out.append({"type": ftype, "flags": flags, "stream": stream, "payload": payload})
        i += 9 + length
    return out


def _h2_settings_entries(payload: bytes) -> list:
    """SETTINGS 载荷 -> ``[(id, value), ...]``（保持线上的条目顺序）。"""
    return [(int.from_bytes(payload[i:i + 2], "big"),
             int.from_bytes(payload[i + 2:i + 6], "big"))
            for i in range(0, len(payload) - 5, 6)]


class H2Server:
    """真·HTTP/2 服务端：ALPN 只提供 ``h2``，不匹配就拒绝（杜绝静默降级）。

    一条连接上由 ``h2`` 状态机驱动，可同时处理多个 stream，响应后保持连接不关，
    便于核对客户端的连接复用与多路复用计数。

    另外按**线上原始字节**记下客户端发的 SETTINGS 条目（保序）、WINDOW_UPDATE
    增量和伪头顺序 —— 这三样就是 HTTP/2 指纹的全部内容，用它们可以核对
    ``diy_fp={"http2_frames": ...}`` / ``akamai=`` 有没有真的落到帧上。
    """

    def __init__(self, certfile, keyfile, host: str = HOST) -> None:
        self._lock = threading.Lock()
        self.connections: list = []      # 每条成功协商 h2 的连接一条记录
        self.refusals: list = []         # ALPN 不匹配 / TLS 握手失败
        self.errors: list = []           # 协商成功之后才出的问题（HTTP/2 协议层等）
        self.streams = 0
        # 最近一个 stream 收到的 header **原样列表**（保序、保重复）。h2 允许同名头
        # 出现多次（Cookie 就允许被拆成多条），折叠成 dict 之后这件事就看不见了。
        self.last_request_headers: list = []
        # 最近一条连接上客户端发的伪头顺序（"masp" 这种），以及 SETTINGS/WINDOW_UPDATE
        self.last_pseudo_order: str = ""

        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._ctx.load_cert_chain(str(certfile), str(keyfile))
        self._ctx.set_alpn_protocols(["h2"])

        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind((host, 0))
        lsock.listen(32)
        lsock.settimeout(0.25)
        self._lsock = lsock
        self.host, self.port = lsock.getsockname()[:2]

        self._stop = threading.Event()
        self._clients: set = set()
        self._threads: list = []
        self._thread = None

    # -- 生命周期 ---------------------------------------------------------- #
    def start(self) -> "H2Server":
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        try:
            self._lsock.close()
        except Exception:  # noqa: BLE001
            pass
        with self._lock:
            clients = list(self._clients)
        for c in clients:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except Exception:  # noqa: BLE001
                pass
            try:
                c.close()
            except Exception:  # noqa: BLE001
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        for t in list(self._threads):
            t.join(timeout=2)

    def url(self, path: str = "/", hostname: str = LOCALHOST) -> str:
        return "https://%s:%d%s" % (hostname, self.port, path)

    # -- 内部 -------------------------------------------------------------- #
    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                self._clients.add(conn)
            t = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            self._threads.append(t)
            t.start()

    def _serve(self, raw: socket.socket) -> None:
        conn = None
        negotiated = False
        try:
            raw.settimeout(10)
            conn = self._ctx.wrap_socket(raw, server_side=True)
            alpn = conn.selected_alpn_protocol()
            if alpn != "h2":
                with self._lock:
                    self.refusals.append({"reason": "alpn=%r (只提供 h2)" % (alpn,)})
                return
            negotiated = True
            self._run_h2(conn)
        except Exception as exc:  # noqa: BLE001
            reason = "%s: %s" % (type(exc).__name__, exc)
            with self._lock:
                (self.errors if negotiated else self.refusals).append({"reason": reason})
        finally:
            with self._lock:
                self._clients.discard(raw)
                self._clients.discard(conn)
            for sock in (conn, raw):
                try:
                    if sock is not None:
                        sock.close()
                except Exception:  # noqa: BLE001
                    pass

    def _run_h2(self, conn: ssl.SSLSocket) -> None:
        state = {"alpn": conn.selected_alpn_protocol(), "tls": conn.version(),
                 "cipher": conn.cipher()[0] if conn.cipher() else None, "streams": 0,
                 "peer_port": conn.getpeername()[1]}
        with self._lock:
            self.connections.append(state)

        h2 = _h2_new_server_connection()
        h2.initiate_connection()
        conn.sendall(h2.data_to_send())

        raw_all = b""          # 客户端明文（preface + 帧），用来抓 SETTINGS/WINDOW_UPDATE
        conn.settimeout(15)   # 保持连接：空闲 15s 才收摊，不是一次性请求-响应

        while not self._stop.is_set():
            try:
                data = conn.recv(65535)
            except socket.timeout:
                break
            except OSError:
                break
            if not data:
                break
            if len(raw_all) < 65536:
                raw_all += data
            self._scan_client_frames(state, raw_all)
            events = h2.receive_data(data)
            terminated = False
            for ev in events:
                if isinstance(ev, _h2_events.RequestReceived):
                    self._respond(h2, conn, ev, state)
                elif isinstance(ev, _h2_events.DataReceived):
                    h2.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, _h2_events.ConnectionTerminated):
                    terminated = True
            out = h2.data_to_send()
            if out:
                conn.sendall(out)
            if terminated:
                break

    def _scan_client_frames(self, state: dict, raw: bytes) -> None:
        """从客户端原始字节里提出 SETTINGS（保序）与 WINDOW_UPDATE。"""
        frames = _h2_scan_frames(raw)
        with self._lock:
            if state.get("settings") is None:
                for fr in frames:
                    # type 4 = SETTINGS；带 ACK(0x1) 的那种载荷为空，跳过
                    if fr["type"] == 0x4 and not (fr["flags"] & 0x1):
                        state["settings"] = _h2_settings_entries(fr["payload"])
                        state["settings_flags"] = fr["flags"]
                        break
            wu = [(fr["stream"], int.from_bytes(fr["payload"][:4], "big"))
                  for fr in frames if fr["type"] == 0x8 and len(fr["payload"]) >= 4]
            if wu:
                state["window_updates"] = wu

    def _respond(self, h2, conn, ev, state: dict) -> None:
        # h2 的 header_encoding 默认是 utf-8（拿到 str），老版本/显式配置下可能是
        # bytes；两种都要能处理，否则修好 client_side 之后这里会以 AttributeError
        # 形式炸成"协议层错误"，把夹具问题伪装成客户端问题。
        headers = {}
        raw_fields: list[tuple[str, str]] = []
        for k, v in ev.headers:
            if isinstance(k, bytes):
                k = k.decode("latin-1")
            if isinstance(v, bytes):
                v = v.decode("latin-1")
            headers[k.lower()] = v
            raw_fields.append((k.lower(), v))
        cookie_fields = [v for k, v in raw_fields if k == "cookie"]
        pseudo_order = "".join(k[1:2] for k, _ in raw_fields if k.startswith(":"))
        with self._lock:
            self.last_request_headers = raw_fields
            self.last_pseudo_order = pseudo_order
            state["pseudo_order"] = pseudo_order
        body = json.dumps({
            "server": "h2", "stream_id": ev.stream_id,
            "path": headers.get(":path", ""), "method": headers.get(":method", ""),
            "authority": headers.get(":authority", ""),
            "stream_seq": state["streams"] + 1,
            # 原样回显：同名头出现了几次、按什么顺序出现，测试直接断言这两件事
            "header_fields": [[k, v] for k, v in raw_fields],
            "cookie_fields": cookie_fields,
        }).encode("utf-8")
        h2.send_headers(ev.stream_id, [
            (":status", "200"),
            ("content-type", "application/json"),
            ("content-length", str(len(body))),
            ("x-local-h2", "1"),
        ], end_stream=False)
        h2.send_data(ev.stream_id, body, end_stream=True)
        with self._lock:
            state["streams"] += 1
            self.streams += 1

    # -- 观测 -------------------------------------------------------------- #
    def connection_count(self) -> int:
        with self._lock:
            return len(self.connections)

    def max_streams_one_connection(self) -> int:
        with self._lock:
            return max([c["streams"] for c in self.connections], default=0)

    def last_settings(self) -> list:
        """最近一条连接上客户端 SETTINGS 的 ``[(id, value), ...]``（保序）。"""
        with self._lock:
            return list(self.connections[-1].get("settings") or []) if self.connections else []

    def last_settings_as_dict(self) -> dict:
        return dict(self.last_settings())

    def last_window_updates(self) -> list:
        """最近一条连接上客户端发的 ``[(stream_id, increment), ...]``。"""
        with self._lock:
            return list(self.connections[-1].get("window_updates") or []) if self.connections else []

    def describe(self) -> dict:
        with self._lock:
            return {"url": "https://%s:%d" % (LOCALHOST, self.port), "port": self.port,
                    "protocol": "HTTP/2", "alpn_offered": ["h2"],
                    "connections": len(self.connections),
                    "streams": self.streams, "refusals": list(self.refusals),
                    "errors": list(self.errors),
                    "max_streams_one_connection": max(
                        [c["streams"] for c in self.connections], default=0)}


# --------------------------------------------------------------------------- #
# 最小 RFC6455 WebSocket 服务端（纯 stdlib，控制帧可观测）
# --------------------------------------------------------------------------- #
class _FrameReader:
    """按 RFC6455 读帧；握手后残留的字节先塞回缓冲。"""

    def __init__(self, sock: socket.socket, initial: bytes = b"") -> None:
        self._sock = sock
        self._buf = bytearray(initial)

    def _need(self, n: int) -> None:
        while len(self._buf) < n:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise ConnectionError("对端关闭连接")
            self._buf += chunk

    def read_frame(self):
        self._need(2)
        b0, b1 = self._buf[0], self._buf[1]
        fin, opcode = bool(b0 & 0x80), b0 & 0x0F
        masked, length = bool(b1 & 0x80), b1 & 0x7F
        idx = 2
        if length == 126:
            self._need(4)
            length = struct.unpack(">H", bytes(self._buf[2:4]))[0]
            idx = 4
        elif length == 127:
            self._need(10)
            length = struct.unpack(">Q", bytes(self._buf[2:10]))[0]
            idx = 10
        mask = b""
        if masked:
            self._need(idx + 4)
            mask = bytes(self._buf[idx:idx + 4])
            idx += 4
        self._need(idx + length)
        payload = bytes(self._buf[idx:idx + length])
        del self._buf[:idx + length]
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return fin, opcode, payload, masked


class _WsConnection:
    def __init__(self, server: "WebSocketServer", sock: socket.socket, ctx) -> None:
        self.server = server
        self._sock = sock
        self._ctx = ctx
        self._initial = b""
        self._reader: _FrameReader | None = None

    # -- 发送 -------------------------------------------------------------- #
    def send_frame(self, opcode: int, payload: bytes = b"") -> None:
        header = bytes([0x80 | opcode])          # FIN=1；服务端帧不加掩码
        n = len(payload)
        if n < 126:
            header += bytes([n])
        elif n < 65536:
            header += bytes([126]) + struct.pack(">H", n)
        else:
            header += bytes([127]) + struct.pack(">Q", n)
        self._sock.sendall(header + payload)

    def _send_text(self, text: str) -> None:
        self.send_frame(OP_TEXT, text.encode("utf-8"))

    # -- 主流程 ------------------------------------------------------------ #
    def serve(self) -> None:
        if self._ctx is not None:
            self._sock = self._ctx.wrap_socket(self._sock, server_side=True)
            self.server.track(self._sock)   # stop() 要能关到真正在用的那个 socket
        self._sock.settimeout(20)
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("握手期对端关闭")
            head += chunk
        head, _, self._initial = head.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        request_line = lines[0]
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers.setdefault(k.strip().lower(), v.strip())
        key = headers.get("sec-websocket-key", "")
        self.server.note_handshake({
            "request_line": request_line,
            "path": request_line.split(" ")[1] if " " in request_line else "",
            "upgrade": headers.get("upgrade", ""),
            "connection": headers.get("connection", ""),
            "version": headers.get("sec-websocket-version", ""),
            "key": key,
            "subprotocol": headers.get("sec-websocket-protocol", ""),
        })
        accept = base64.b64encode(hashlib.sha1(key.encode("latin-1") + _WS_GUID).digest())
        self._sock.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")

        reader = _FrameReader(self._sock, self._initial)
        self._reader = reader
        frag_op, frag = None, bytearray()
        while True:
            fin, opcode, payload, masked = reader.read_frame()
            if not masked:
                self.server.note_error("客户端数据帧未加掩码（RFC6455 违规）")
            if opcode == OP_PING:
                self.server.note_ping(payload)
                self.send_frame(OP_PONG, payload)
                continue
            if opcode == OP_PONG:
                self.server.note_pong(payload)
                if payload == WS_PING_PROBE:
                    self._send_text(WS_PONG_OK)
                continue
            if opcode == OP_CLOSE:
                self.server.note_close(payload[:2] if len(payload) >= 2 else None)
                self.send_frame(OP_CLOSE, payload[:2] if len(payload) >= 2 else b"")
                return
            if opcode in (OP_TEXT, OP_BINARY):
                if fin:
                    if not self._handle_data(opcode, bytes(payload)):
                        return
                else:
                    frag_op, frag = opcode, bytearray(payload)
                continue
            if opcode == OP_CONT:
                frag += payload
                if fin and frag_op is not None:
                    done = self._handle_data(frag_op, bytes(frag))
                    frag_op, frag = None, bytearray()
                    if not done:
                        return
                continue
            self.server.note_error("未知 opcode=0x%x" % opcode)

    def _handle_data(self, opcode: int, payload: bytes) -> bool:
        """返回 False 表示服务端要收摊（已主动发 CLOSE）。"""
        if opcode == OP_BINARY:
            self.server.note_binary(payload)
            self.send_frame(OP_BINARY, payload)
            return True
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            self.server.note_error("文本帧不是合法 UTF-8")
            text = None
        self.server.note_text(text if text is not None else payload)
        if text == WS_CMD_PING:
            self.send_frame(OP_PING, WS_PING_PROBE)
            return True
        if text == WS_CMD_CLOSE:
            self.server.note_server_close()
            self.send_frame(OP_CLOSE, struct.pack(">H", 1000))
            self._sock.settimeout(2.0)      # 等客户端的 CLOSE 回帧，不来就算了
            try:
                while True:
                    _, opcode, payload, _ = self._reader.read_frame()
                    if opcode == OP_CLOSE:
                        self.server.note_close(payload[:2] if len(payload) >= 2 else None)
                        return False
            except (OSError, ConnectionError):
                return False
        if text is not None:
            self._send_text(text)
        else:
            self.send_frame(OP_BINARY, payload)
        return True


class WebSocketServer:
    """RFC6455 服务端：回显 text/binary、可发 PING 验证客户端 PONG、双向 CLOSE。"""

    def __init__(self, certfile=None, keyfile=None, host: str = HOST) -> None:
        self._lock = threading.Lock()
        self.handshakes: list = []
        self.texts: list = []
        self.binaries: list = []
        self.pings: list = []          # 客户端发来的 PING 载荷
        self.pongs: list = []          # 客户端回给我们的 PONG 载荷
        self.closes: list = []         # 客户端 CLOSE 的状态码（无载荷记 None）
        self.server_closes = 0
        self.errors: list = []         # 协议违规 / 非预期异常
        self.notes: list = []          # 正常的收尾（EOF、socket.timeout 等）
        self.connections = 0
        self._clients: set = set()
        self._threads: list = []
        self._thread = None

        self._ctx = None
        if certfile is not None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(str(certfile), str(keyfile))
            ctx.set_alpn_protocols(["http/1.1"])
            self._ctx = ctx

        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind((host, 0))
        lsock.listen(16)
        lsock.settimeout(0.25)
        self._lsock = lsock
        self.host, self.port = lsock.getsockname()[:2]
        self.scheme = "wss" if self._ctx is not None else "ws"
        self._stop = threading.Event()

    # -- 记账（handler 线程调用） ------------------------------------------ #
    def _note(self, attr: str, value) -> None:
        with self._lock:
            getattr(self, attr).append(value)

    def note_handshake(self, info: dict) -> None:
        self._note("handshakes", info)

    def note_text(self, text) -> None:
        self._note("texts", text)

    def note_binary(self, data: bytes) -> None:
        self._note("binaries", data)

    def note_ping(self, payload: bytes) -> None:
        self._note("pings", payload)

    def note_pong(self, payload: bytes) -> None:
        self._note("pongs", payload)

    def note_close(self, code) -> None:
        self._note("closes", code)

    def note_error(self, message: str) -> None:
        self._note("errors", message)

    def note_note(self, message: str) -> None:
        self._note("notes", message)

    def note_server_close(self) -> None:
        with self._lock:
            self.server_closes += 1

    def track(self, sock) -> None:
        with self._lock:
            self._clients.add(sock)

    def snapshot(self) -> dict:
        with self._lock:
            return {"connections": self.connections, "handshakes": list(self.handshakes),
                    "texts": list(self.texts), "binaries": list(self.binaries),
                    "pings": list(self.pings), "pongs": list(self.pongs),
                    "closes": list(self.closes), "server_closes": self.server_closes,
                    "errors": list(self.errors), "notes": list(self.notes)}

    # -- 生命周期 ---------------------------------------------------------- #
    def url(self, path: str = "/", hostname: str = LOCALHOST) -> str:
        return "%s://%s:%d%s" % (self.scheme, hostname, self.port, path)

    def start(self) -> "WebSocketServer":
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        try:
            self._lsock.close()
        except Exception:  # noqa: BLE001
            pass
        with self._lock:
            clients = list(self._clients)
        for c in clients:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except Exception:  # noqa: BLE001
                pass
            try:
                c.close()
            except Exception:  # noqa: BLE001
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                self.connections += 1
                self._clients.add(conn)
            t = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            self._threads.append(t)
            t.start()

    def _serve(self, conn: socket.socket) -> None:
        handler = _WsConnection(self, conn, self._ctx)
        try:
            handler.serve()
        except (ConnectionError, OSError) as exc:
            # 正常收尾（对端直接关、读超时、TLS 握手被客户端拒绝）不算协议错误
            self.note_note("%s: %s" % (type(exc).__name__, exc))
        except Exception as exc:  # noqa: BLE001
            self.note_error("%s: %s" % (type(exc).__name__, exc))
        finally:
            with self._lock:
                self._clients.discard(conn)
                self._clients.discard(handler._sock)

    def describe(self) -> dict:
        snap = self.snapshot()
        snap.update({"url": "%s://%s:%d" % (self.scheme, LOCALHOST, self.port),
                     "protocol": "WebSocket(RFC6455)", "tls": self._ctx is not None,
                     "port": self.port})
        return snap
