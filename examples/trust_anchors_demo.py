#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""trust_anchors(51764) 扩展怎么用 —— 可运行示例。

背景（30 秒版）
===============
Chrome 的 ClientHello 里有一个扩展开关 51764 ``trust_anchors``，载荷是
一串「信任锚 ID」（Chrome 内置根存储里每张根证书的编号）。JA3/JA4 里表现为
扩展列表末尾多一个 ``51764``，所以会被部分检测站当成"新版 Chrome 的特征"。

* 内置预设 ``chrome155`` **默认就会发**这 28 项，你什么都不用配；
* 想换一份（比如你抓到了某个特定版本 Chrome 的列表），用
  ``diy_fp={"tls_trust_anchors": "..."}`` 覆盖；
* 顺序：**按你给的顺序原样发出，不做任何重排**。真 Chrome（155）把这 28 项按
  RELATIVE-OID 编码字节排序后固定发送 —— 每一条连接、每一次浏览器启动，收到的
  都是同一份 186 字节；内置预设存的就是这份序。

先跑起来
========
    cd python
    python examples/trust_anchors_demo.py

脚本不连外网：用一个"只收不答"的本地监听，把 nb_curl 真正发出的第一条
ClientHello 抓下来解扩展表，直接打印线上到底发了哪一份。运行时看到客户端
报连接错误是**预期**的（服务端故意不回应）。
"""

from __future__ import annotations

import os
import socket
import sys
import threading

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)                      # <repo>/python
if os.path.isdir(os.path.join(_ROOT, "nb_curl")):
    sys.path.insert(0, _ROOT)

import nb_curl  # noqa: E402

# Chrome 内置根存储的 28 项 trust anchor ID（从真实 Chrome 155 抓包解出，与内置预设 ``chrome155`` 同一份）。
CHROME_ANCHORS = (
    "52580.200109.1.10", "44947.2.1", "52580.200109.1.7", "11129.9.11",
    "44947.2.6", "11129.9.5", "11129.9.10", "44947.2.18",
    "52580.200109.1.13", "11129.9.8", "11129.9.13", "11129.9.12",
    "52580.200109.1.19", "52580.200109.1.12", "44947.2.19",
    "52580.200109.1.9", "11129.9.4", "11129.9.1", "52580.200109.1.18",
    "11129.9.15", "44947.2.13", "52580.200109.1.8", "44947.2.14",
    "11129.9.6", "44947.2.15", "52580.200109.1.11", "11129.9.7",
    "44947.2.20",
)

TA_EXTENSION_ID = 51764


# --------------------------------------------------------------------------- #
# 抓自己的 ClientHello（不需要证书，也不需要外网）
# --------------------------------------------------------------------------- #
def _decode_trust_anchors(blob: bytes) -> list[str]:
    """51764 的载荷 -> OID 列表。

    线格式：``u16 总长`` + 若干「``u8`` 长度 + ASN.1 RELATIVE-OID」。
    每个数字按 base-128 编码：字节高位置 1 表示"后面还有字节"。
    注意：**空列表的编码是 ``0000``**（总长 0），跟"扩展整个不存在"是两回事。
    """
    total = int.from_bytes(blob[:2], "big")
    body, pos, out = blob[2:2 + total], 0, []
    while pos < len(body):
        ln = body[pos]
        pos += 1
        arcs: list[int] = []
        value = 0
        for byte in body[pos:pos + ln]:
            value = (value << 7) | (byte & 0x7F)
            if not byte & 0x80:
                arcs.append(value)
                value = 0
        out.append(".".join(str(a) for a in arcs))
        pos += ln
    return out


def _client_hello_extensions(record: bytes) -> dict[int, bytes]:
    """一条 TLS 记录 -> ClientHello 的扩展表 ``{扩展 id: 原始载荷}``。"""
    hs = record[5:]                                   # 去掉 5 字节 TLS 记录头
    if hs[0] != 1:
        raise RuntimeError("第一条握手不是 ClientHello: type=%d" % hs[0])
    ch = hs[4:]                                       # 去掉 4 字节握手头
    p = 2 + 32                                        # legacy_version + random
    p += 1 + ch[p]                                    # session_id
    p += 2 + int.from_bytes(ch[p:p + 2], "big")       # cipher_suites
    p += 1 + ch[p]                                    # compression_methods
    end = p + 2 + int.from_bytes(ch[p:p + 2], "big")
    p += 2
    exts: dict[int, bytes] = {}
    while p + 4 <= end:
        eid = int.from_bytes(ch[p:p + 2], "big")
        elen = int.from_bytes(ch[p + 2:p + 4], "big")
        exts[eid] = ch[p + 4:p + 4 + elen]
        p += 4 + elen
    return exts


def sniff_client_hello(**session_kwargs) -> dict[int, bytes]:
    """起一个只收不答的 TCP 监听，返回 nb_curl 发出的第一条 ClientHello 的扩展表。"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    box: dict = {}

    def _serve() -> None:
        try:
            conn, _ = srv.accept()
            conn.settimeout(8)
            buf = b""
            while len(buf) < 5:
                chunk = conn.recv(4096)
                if not chunk:
                    raise RuntimeError("客户端在发出握手前就断开了")
                buf += chunk
            need = 5 + int.from_bytes(buf[3:5], "big")
            while len(buf) < need:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
            box["record"] = buf[:need]
            conn.close()
        except Exception as exc:  # noqa: BLE001
            box["error"] = exc
        finally:
            try:
                srv.close()
            except OSError:
                pass

    th = threading.Thread(target=_serve, daemon=True)
    th.start()
    try:
        nb_curl.get("https://127.0.0.1:%d/" % port, verify=False, timeout=8,
                    **session_kwargs)
    except Exception:  # noqa: BLE001
        pass          # 服务端故意不回应，客户端必然失败，属预期
    th.join(10)
    if "record" not in box:
        raise RuntimeError("没拿到 ClientHello: %r" % (box.get("error"),))
    return _client_hello_extensions(box["record"])


def show(title: str, exts: dict[int, bytes]) -> list[str]:
    """打印扩展 51764 的情况，返回解出的 OID 列表。"""
    print("=" * 72)
    print(title)
    print("=" * 72)
    if TA_EXTENSION_ID not in exts:
        print("  线上没有发 51764 扩展（换一个带该扩展的预设/自定义才会出现）")
        return []
    payload = exts[TA_EXTENSION_ID]
    anchors = _decode_trust_anchors(payload)
    print("  扩展 51764 载荷长度 : %d 字节" % len(payload))
    print("  信任锚条数         : %d" % len(anchors))
    if not anchors:
        print("  内容               : 空列表（线格式 0000）")
    else:
        print("  前 4 条            : %s" % ", ".join(anchors[:4]))
    print("  本进程内是否等于 Chrome 28 项全集: %s"
          % ("是（只是排列不同）" if sorted(anchors) == sorted(CHROME_ANCHORS)
             else "否"))
    print()
    return anchors


def main() -> int:
    print("\nnb_curl %s  backend=%s\n" % (nb_curl.__version__, nb_curl.backend_name()))

    # --- 1. 默认：chrome155 自带 Chrome 的 28 项，什么都不用配 ---
    default_anchors = show(
        "1) 默认 chrome155（不传 diy_fp）",
        sniff_client_hello(impersonate="chrome155"))

    # --- 2. 自定义：只发你指定的两条 ---
    custom = "52580.200109.1.10,11129.9.1"
    custom_anchors = show(
        "2) diy_fp={'tls_trust_anchors': %r}" % custom,
        sniff_client_hello(impersonate="chrome155",
                           diy_fp={"tls_trust_anchors": custom}))

    # --- 3. 显式发空列表（线格式 0000）---
    show("3) diy_fp={'tls_trust_anchors': ''}   # 发空列表",
         sniff_client_hello(impersonate="chrome155",
                            diy_fp={"tls_trust_anchors": ""}))

    # --- 4. 同一进程内连发两次：顺序应当逐项相同（跨进程也不变）---
    again = sniff_client_hello(impersonate="chrome155")
    same = (_decode_trust_anchors(again[TA_EXTENSION_ID]) == default_anchors)
    print("=" * 72)
    print("4) 同一进程内第二次连接是否与第一次逐项相同: %s" % ("是" if same else "否"))
    print("   真实 Chrome 也是这样：每连接同一份字节，换一次启动也还是同一份。")
    print()

    # --- 5. 一份"从别处抓来的列表"怎么喂进来 ---
    #     拿到十六进制载荷时，用 nb_curl.xcctls._decode_trust_anchors 解成
    #     逗号分隔的字符串，再塞进 diy_fp 即可：
    #
    #         from nb_curl.xcctls import _decode_trust_anchors
    #         oids = _decode_trust_anchors("00b804d67909040582df1302...")
    #         Session(impersonate="chrome155",
    #                 diy_fp={"tls_trust_anchors": oids})
    #
    #     手里只有一份 xcctls /all 快照 JSON 时更省事：
    #
    #         from nb_curl import parse_xcctls
    #         fp = parse_xcctls(open("snapshot.json").read())
    #
    #     （快照里 51764 的载荷通常是空的，那时会保留底座预设的 28 项并给一条
    #      warning —— 因为"没 dump 出载荷"不等于"对方发的是空列表"。）

    print("=" * 72)
    print("小结")
    print("=" * 72)
    print("  默认                 : chrome155 已带 Chrome 28 项，无需配置")
    print("  顺序                 : 原样发出、不重排（预设 = 真 Chrome 155 的顺序）")
    print("  换一份               : diy_fp={'tls_trust_anchors': 'OID, OID, ...'}")
    print("  发空列表             : diy_fp={'tls_trust_anchors': ''}")
    print("  字段类型/说明         : nb_curl.diy_fp_fields()['tls_trust_anchors']")
    print("  和别的 diy_fp 字段可共存（一起写进同一个 dict）")
    print()
    print("  本次实测：默认 %d 项 / 自定义 %d 项"
          % (len(default_anchors), len(custom_anchors)))
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
