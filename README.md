# nb-curl

一个**基于 [curl-impersonate](https://github.com/lwthiker/curl-impersonate) 的 Python HTTP 客户端**：
底层是 libcurl + BoringSSL，可以模拟真实浏览器的 **TLS 指纹（ja3 / ja4）** 和 **HTTP/2 指纹**，
让 Python 发出去的请求在网络层更贴近浏览器；上层是 requests 风格、简单好用的 API。

```python
from nb_curl import requests

r = requests.get("https://www.xcctls.top/all", impersonate="chrome152")
print(r.status_code, r.http_version)   # 200 2
```

---

## 安装

```bash
pip install nb-curl

# 或下载 wheel 手动装（Releases 页有 Windows x64 / Linux x86_64）
pip install nb_curl-0.2.1-py3-none-win_amd64.whl
```

支持平台：Windows x64、Linux x86_64。

---

## 模拟能力与性能

**指纹模拟**：内置 40 套真实浏览器预设（Chrome / Edge / Firefox / Safari / OkHttp / Tor），
直接由 C 内核完成，零 Python 开销；`ja3` / `akamai` / `diy_fp` / 指纹快照可以在运行时自由覆盖，
**改指纹不用重新编译**。

有个现成的照妖镜可以验证：[https://www.xcctls.top/score](https://www.xcctls.top/score)
—— 一个给 HTTP 请求打分的检测站，满分 100，从 UA、ECH、TLS ClientHello 各项（与 Chrome 基线逐项比对）、
HTTP/2 指纹与请求头等维度扣分。内置预设实测：

| 预设 | xcctls 评分 |
| --- | --- |
| `chrome152` | **95 / 100** |
| `chrome150` | **95 / 100** |

**并发性能**：

| 指标 | 实测值 |
| --- | --- |
| 综合加权得分 | **3.24 / 5**（6 库中最高） |
| 明文 HTTP/1.1 · 100 线程 | **4903 RPS**（P50 15.9 ms / P95 25.7 ms） |
| TLS + HTTP/2 · 100 线程 | **4492 RPS** |
| TLS + HTTP/2 · 异步 100 并发 | **3207 RPS** |
| 每请求 CPU（并发 50） | **0.36 ms** |
| 冷连接「建连 → 首字节」P50 | **7.58 ms** |
| 各场景错误率 | **0.0%** |

这是"高并发时仍然保持完整浏览器指纹"的实测表现。

> 想直观看自己的裸指纹长什么样：[https://www.xcctls.top/all](https://www.xcctls.top/all)
> 会把你这台客户端的 **TLS ClientHello 结构 + ja3 + ja4 + HTTP/2 SETTINGS / akamai 指纹 + 请求头**
> 整份 dump 成 JSON。下面要讲的 `fp_file` 就是直接吃这份 JSON。

---

## 示例

### 同步

```python
import nb_curl

# 一次性请求
r = nb_curl.get("https://www.xcctls.top/all", impersonate="chrome152", timeout=15)
r.status_code          # 200
r.json()               # dict
r.http_version         # "2"

# 会话：保持 cookie、复用连接
with nb_curl.Session(impersonate="chrome146") as s:
    s.get("https://example.com/login")
    s.post("https://example.com/api", json={"user": "a"})
    s.get("https://example.com/profile")
```

### 异步 —— 用 `with`

```python
import asyncio
import nb_curl

async def main():
    async with nb_curl.AsyncSession(impersonate="chrome152", max_clients=20) as s:
        r = await s.get("https://example.com")
        print(r.status_code)

        # 并发
        rs = await asyncio.gather(*[s.get(u) for u in urls])

asyncio.run(main())
```

### 异步 —— 不用 `with`

```python
import asyncio
import nb_curl

async def main():
    s = nb_curl.AsyncSession(impersonate="chrome152", max_clients=20)
    try:
        r = await s.get("https://example.com")
        print(r.status_code)
    finally:
        await s.close()          # close() 是 async 方法，要 await

asyncio.run(main())
```

### 其它常用参数

```python
nb_curl.get(
    url,
    http_version="1.1",                              # 强制 HTTP 版本
    proxies={"https": "socks5h://127.0.0.1:7890"},   # 代理
    verify=False,                                    # 不校验证书
    allow_redirects=False,                           # 不跟随跳转
)
```

---

## TLS / HTTP2 指纹模拟

指纹有两种来源：**内置预设**（C 内核，零开销）和**运行时自定义**（灵活，不用重编译）。

### 内置浏览器预设

`impersonate=` 直接填名字：

| 家族 | 预设 |
| --- | --- |
| **Chrome** | `chrome99` · `chrome99_android` · `chrome100` · `chrome101` · `chrome104` · `chrome107` · `chrome110` · `chrome116` · `chrome119` · `chrome120` · `chrome123` · `chrome124` · `chrome131` · `chrome131_android` · `chrome133a` · `chrome136` · `chrome142` · `chrome145` · `chrome146` · `chrome150` · `chrome152` |
| **Edge** | `edge99` · `edge101` |
| **Firefox** | `firefox133` · `firefox135` · `firefox144` · `firefox147` |
| **Safari** | `safari153` · `safari155` · `safari170` · `safari172_ios` · `safari180` · `safari180_ios` · `safari184` · `safari184_ios` · `safari260` · `safari2601` · `safari260_ios` |
| **OkHttp** | `okhttp4_android` |
| **Tor** | `tor145` |

也可以填**家族别名**，自动解析到该家族最新版：`chrome`、`firefox`、`safari`、`edge`、`okhttp`、`tor`。

给预设加 `:no` 后缀，可以只套 TLS/H2 指纹、**不带**该浏览器的默认请求头：

```python
nb_curl.get(url, impersonate="chrome152:no")
```

运行期想确认本机有哪些可用：

```python
import nb_curl
nb_curl.available_targets()        # 本机真正可用的 target 列表
nb_curl.is_available("chrome150")  # True
```

### 自定义指纹

下面几种手段可以自由组合（后者覆盖前者）：**快照打底 → 预设 → ja3/akamai → diy_fp**。

#### `impersonate` —— 换预设，最简单

```python
nb_curl.get(url, impersonate="firefox147")
```

#### `ja3` —— 直接给 TLS 指纹字符串

格式 `TLSVersion,Ciphers,Extensions,Groups,ECPointFormats`，覆盖预设的 TLS 层：

```python
nb_curl.get(
    url,
    ja3="771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-"
        "156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,4588-29-23-24,0",
)
```

套件 / 扩展 / 曲线会自动映射成名字，GREASE 会自动过滤。

#### `akamai` —— HTTP/2 指纹

格式 `SETTINGS|WINDOW_UPDATE|STREAMS|PSEUDO_HEADER_ORDER`：

```python
nb_curl.get(url, akamai="1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p")
```

#### `diy_fp` —— 字段级微调

```python
nb_curl.get(url, impersonate="chrome150", diy_fp={
    "tls_grease": True,              # 插 GREASE
    "tls_permute_extensions": True,  # 扩展顺序随机
    "http2_no_priority": True,
})
```

可用键见 `nb_curl.diy_fp_fields()`，拼错会直接报错，不会静默忽略。

#### `fp_file` —— 一键复刻真实浏览器（最省事）

**这是最简单的方式：不用懂上面任何参数。**

用真浏览器打开 [https://www.xcctls.top/all](https://www.xcctls.top/all)，把返回的 JSON 存成一个文件，
然后直接喂给 `fp_file` —— 那个浏览器的**完整指纹（含默认请求头）就被逐字段复刻**了：

```python
# 1) 存成文件，直接传路径
nb_curl.get(url, fp_file="real_chrome.json")

# 2) 已经是 dict / JSON 文本，也可以直接给
import json, pathlib
snap = json.loads(pathlib.Path("real_chrome.json").read_text("utf-8"))
nb_curl.get(url, fp_file=snap)

# 3) 想反复用，可以先解析成 Fingerprint 对象，当"预设"一样使
fp = nb_curl.parse_xcctls(open("real_chrome.json", encoding="utf-8").read())
nb_curl.get(url, impersonate=fp)
```

`fp_file` 和 `impersonate` 可以叠加：**快照打底，显式参数覆盖**。

```python
nb_curl.get(url, fp_file="real_chrome.json", impersonate="chrome152")
```

想换浏览器？在浏览器里重新打开一次 `/all`、存成新 JSON 就行。

### 取值范围自省 —— 不用猜，传错立刻报错

不确定某个值是否合法，用 `nb_curl.tls` 查（全部离线可用）：

```python
nb_curl.tls.supported_ciphers()                # 37 个密码套件
nb_curl.tls.supported_tls13_ciphers()
nb_curl.tls.supported_groups()                 # 9 个曲线/协商组
nb_curl.tls.supported_signature_algorithms()   # 16 个签名算法
nb_curl.tls.supported_extensions()             # 32 个合法扩展 id
nb_curl.tls.supported_tls_versions()           # ("1.0", "1.1", "1.2", "1.3")
nb_curl.tls.supported_cert_compression()       # ("brotli", "zlib", "zstd")
nb_curl.diy_fp_fields()                        # diy_fp 的合法键
```

传了非法值，会在请求发出去之前就抛 `FingerprintError`，不会等到建连时报一个看不懂的 CURLcode：

```python
nb_curl.get(url, diy_fp={"tls_cert_compression": "lz4"})
# FingerprintError: tls_cert_compression: 算法 'lz4' 不支持。允许的取值: brotli, zlib, zstd
```

---

## 常见问题

**Q：指纹改了不生效？**
TLS 指纹只在**建立连接**时生效，连接一旦建立就固定了。nb-curl 已经用"连接池按指纹分 key"处理了这件事——
同一个 `Session` 里切换 `impersonate` 会自动换连接。如果你自己缓存了连接，注意这一点。

**Q：某些站点报 `Error in the HTTP2 framing layer`？**
有些服务端每次响应后都会关闭 HTTP/2 连接，库会尝试复用已死连接。nb-curl 会自动新建连接重试，
并记住该 origin 后续直接新建连接。可用 `max_retries=0` 关闭该行为（只对幂等方法重试）。

**Q：代理怎么写？**
最简单：`proxy="socks5h://user:pass@host:port"`，对所有请求生效。
要按协议区分就用 `proxies={"http": "http://...", "https": "socks5h://..."}`。
只写一个键也行，`proxies={"https": ...}` 或 `proxies={"all": ...}` 都能覆盖全部请求；
但只写 `{"http": ...}` 时 https 请求不走代理（直连）。`proxy` 与 `proxies` 同时给出时 `proxy` 优先。

---

## License

本项目采用 **[MIT License](LICENSE)**。

需要说明的是：本仓库发布的 wheel 里**静态链接了以下第三方组件**，使用 / 再分发时请一并遵守它们的许可：

- **curl**（MIT/X 风格）
- **BoringSSL**（ISC + OpenSSL 双许可）
- **nghttp2**（MIT）
- **curl-impersonate**（MIT）

---

## 致谢

- 指纹内核来自 [curl-impersonate](https://github.com/lwthiker/curl-impersonate)。
- 反指纹效果的可视化检测由 [xcctls](https://www.xcctls.top/) 提供：[/score 打分](https://www.xcctls.top/score) · [/all 指纹查看](https://www.xcctls.top/all)。
