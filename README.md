# nb-curl

一个**基于 [curl-impersonate](https://github.com/lwthiker/curl-impersonate) 的 Python HTTP 客户端**：
底层是 libcurl + BoringSSL，可以模拟真实浏览器的 **TLS 指纹（ja3 / ja4）**、**HTTP/2 指纹**
和 **HTTP/3 指纹**，让 Python 发出去的请求在网络层更贴近浏览器；上层是 requests 风格、简单好用的 API。

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
pip install nb_curl-0.3.0-py3-none-win_amd64.whl
```

支持平台：Windows x64、Linux x86_64。

---

## 模拟能力与性能

**指纹模拟**：内置 40 套真实浏览器预设（Chrome / Edge / Firefox / Safari / OkHttp / Tor），
直接由 C 内核完成，零 Python 开销；`ja3` / `akamai` / `diy_fp` / 指纹快照可以在运行时自由覆盖，
**改指纹不用重新编译**。

有个现成的照妖镜可以验证：[https://www.xcctls.top/score](https://www.xcctls.top/score)
—— 一个给 HTTP 请求打分的检测站，满分 100，从 UA、ECH、TLS ClientHello 各项（与 Chrome 基线逐项比对）、
HTTP/2 指纹与请求头等维度扣分。同一台机器、同一个检测站，实测评分：

| 客户端 | xcctls 评分 |
| --- | --- |
| Chrome 浏览器（基线） | **100 / 100** |
| **nb-curl** | **95 / 100** |
| requests_go | 85 / 100 |
| curl_cffi | 79 / 100 |

**能力速览**（★ 越多越强；☆ = 该库不提供这项能力）：

| 库 | HTTP/2 | HTTP/3 | 异步 | WebSocket | 指纹模拟 | 性能 |
| --- | :--: | :--: | :--: | :--: | :--: | :--: |
| **nb-curl** | ★★★★★ | ★★★★★ | ★★★★★ | ★★★★★ | ★★★★★ | ★★★★☆ |
| curl_cffi | ★★★★★ | ★★★★★ | ★★★★★ | ★★★★★ | ★★★★☆ | ★★★☆☆ |
| requests_go | ★★★★★ | ☆☆☆☆☆ | ☆☆☆☆☆ | ☆☆☆☆☆ | ★★★★☆ | ★★★☆☆ |
| httpx | ★★★★☆ | ☆☆☆☆☆ | ★★★★☆ | ☆☆☆☆☆ | ☆☆☆☆☆ | ★★☆☆☆ |
| aiohttp | ☆☆☆☆☆ | ☆☆☆☆☆ | ★★★★★ | ★★★★★ | ☆☆☆☆☆ | ★★★★★ |
| requests | ☆☆☆☆☆ | ☆☆☆☆☆ | ☆☆☆☆☆ | ☆☆☆☆☆ | ☆☆☆☆☆ | ★★★☆☆ |

「性能」看的是各库在最擅长模型下的吞吐与 CPU 效率（并发 64～1024）。星级只是粗略归纳，
具体数字与口径见下方报告。

### 性能实测

下面是横向评测里的几张原始图（客户端与服务端同机回环、各自绑核，每一格都是实测）：

**吞吐随并发的变化** —— 明文 HTTP/1.1，128 字节响应；低并发段看单连接开销，高并发段看调度成本。

![并发吞吐曲线](benchmarks/charts/3-1-throughput-vs-concurrency.svg)

**各并发档位吞吐** —— 同一份数据的柱状视图，便于逐档对比。

![各并发档位吞吐](benchmarks/charts/3-2-throughput-by-concurrency.svg)

**CPU 效率** —— 每请求客户端 CPU 毫秒，越低越好；浏览器仿真多做的那部分工作在这里直接量化。

![CPU 效率（每请求客户端 CPU 毫秒）](benchmarks/charts/3-4-cpu-per-request.svg)

**指纹评分** —— 第三方检测站 [xcctls](https://www.xcctls.top/score) 打分（满分 100，越高越接近真实 Chrome）。

![请求指纹评分](benchmarks/charts/4-fingerprint-score.svg)

> **[→ 完整评测报告](benchmarks/README.md)** —— GitHub 直接渲染的 Markdown 版，含全部 12 张图
> 与完整数据表；报告同样提供单文件 HTML 版：[`benchmarks/report.html`](benchmarks/report.html)
> （[在线预览](https://htmlpreview.github.io/?https://github.com/touxigua00/nb-curl/blob/main/benchmarks/report.html)）。
> 内容：nb-curl 与 requests / aiohttp / httpx / curl_cffi / requests_go 六个库的
> **功能、性能、指纹评分**横向对比。

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

### 异步

```python
import asyncio
import nb_curl

async def main():
    # 推荐：with 会自动关闭
    async with nb_curl.AsyncSession(impersonate="chrome152", max_clients=20) as s:
        r = await s.get("https://example.com")
        print(r.status_code)
        rs = await asyncio.gather(*[s.get(u) for u in urls])    # 并发

    # 不想用 with，就自己收尾 —— close() 是 async 方法，要 await
    s = nb_curl.AsyncSession(impersonate="chrome152", max_clients=20)
    try:
        r = await s.get("https://example.com")
    finally:
        await s.close()

asyncio.run(main())
```

### 其它常用参数

```python
nb_curl.get(
    url,
    http_version="1.1",                              # 强制 HTTP 版本；换成 "3" 或 30 就是 HTTP/3
    proxies={"https": "socks5h://127.0.0.1:7890"},   # 代理
    tcp="64240_2-1-3-1-1-4_1400_8",                  # TCP 层画像（JA4T）
    h2_priority=False,                               # HEADERS 帧不带优先级字段
    verify=False,                                    # 不校验证书
    allow_redirects=False,                           # 不跟随跳转
)
```

### 参数忘了怎么传？查这里

所有支持的参数、每个参数的合法取值，都能直接在运行时查出来 —— 不用翻文档：

```python
import nb_curl

print(nb_curl.params.describe())         # 全部参数一览（带取值说明）
print(nb_curl.params.describe("tcp"))    # 只看一个参数
help(nb_curl.params.RequestOptions)      # 类型定义 + 逐项说明
```

像 `tcp`、`resolve`、`http_version` 这种「知道能传字典、但不知道键怎么填」的参数，
输出里都写明了键名、取值范围和示例。

参数名写错不会被静默忽略，会在发请求前直接报 `TypeError`，并提示最接近的合法参数名。

### TCP 层画像（JA4T）

`tcp=` 在**建连之前**按 socket 设定 TCP 层参数，让 JA4T 画像和目标一致。
它收**完整的 JA4T 值**（`"窗口_选项顺序_MSS_窗口缩放"`），也收只写关心字段的 dict：

```python
nb_curl.get(url, tcp="64240_2-1-3-1-1-4_1400_8")     # 完整值
nb_curl.Session(tcp={"window": 64240, "wscale": 0})   # 只给关心的字段
nb_curl.get(url, ttl=77)                              # 只改 TTL（也可写进 tcp=）
nb_curl.get(url, timestamps=True)                     # TCP 时间戳
```

三条约定：

- **本机做不到的项只发警告，不报错**，请求照发，只是该项不生效。
  关掉警告：`nb_curl.set_tcp_warnings(False)`，或
  `warnings.simplefilter("ignore", nb_curl.TCPShapeWarning)`。
  只有画像串本身写错（格式 / 类型 / 取值越界）才抛 `nb_curl.TCPShapeError`。
- **默认窗口绝不被改动**：只要给出的 `window` / `wscale` 这一对不能同时精确达成，
  就完全不碰本机窗口（Windows 上常见 `64240`），只发一条警告说明哪一项做不到。
- **TCP option 顺序任何系统都改不了**（写在内核里，没有接口），顺序段只能填本机原生值，
  否则发警告：Windows `2-1-3-1-1-4`、Linux `2-4-8-1-3`。

各观测点的平台能力、落点、能不能回读证实，用 `nb_curl.tcp_support()` 查：

```python
nb_curl.tcp_support()
# {'platform': ..., 'native_order': '2-1-3-1-1-4',
#  'knobs': {'ttl': True, 'mss': True, 'window': True, 'wscale': True, 'timestamp': True},
#  'verifiable': {...}, 'mss_mechanism': 'interface-mtu', 'ts_mechanism': 'socket', ...}
```

Linux 上 MSS 逐 socket 生效（`mss=1200` 时对端读到的就是 `1200`，走 `TCP_MAXSEG`）；
Windows 上只能靠改网卡 MTU（`MSS = MTU - 40`，需管理员）。TTL 是最便宜也最有效的一项 ——
检测站按 TTL 判 OS，只改 options 不改 TTL 会被判成 `Unknown`。

### HTTP/2 优先级字段

`h2_priority=` 控制 HEADERS 帧里是否带 RFC 7540 的优先级字段（`E` / 依赖 / 权重）。
Chrome 系导航请求默认带（HEADERS flags `0x25`），需要「不带」时用 `h2_priority=False`
（flags `0x05`）。不传则跟随所选指纹预设。与 `diy_fp` 的 `http2_no_priority`
互斥，两个一起给会报 `FingerprintError`。

---

## TLS / HTTP2 / HTTP3 指纹模拟

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

#### `trust_anchors`（扩展 51764）—— 内置预设已带，通常不用管

Chrome 152 的 ClientHello 多了一个 `trust_anchors(51764)` 扩展，载荷是 Chrome 内置
根存储里每张根证书的编号。**`chrome152` 预设默认就发这 28 项**，你什么都不用配；
只有要换一份时才写：

```python
# 默认：自带 Chrome 的 28 项
nb_curl.get(url, impersonate="chrome152")

# 换成自己的列表（逗号分隔的十进制点分 OID）
nb_curl.get(url, impersonate="chrome152",
            diy_fp={"tls_trust_anchors": "52580.200109.1.10,11129.9.1"})

# 显式发空列表（线格式 "0000"，和"扩展不存在"不是一回事）
nb_curl.get(url, impersonate="chrome152",
            diy_fp={"tls_trust_anchors": ""})
```

排列在**单次进程内固定**、换进程才可能变 —— 与真实 Chrome 一致（一次运行内几十条
连接字节全同）。想确认线上到底发了什么，跑仓库里的离线示例
（用"只收不答"的本地监听截下第一条 ClientHello 再解扩展表）：

```bash
python examples/trust_anchors_demo.py
```

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

## HTTP/3

**nb-curl 支持 HTTP/3**（底层 ngtcp2 + nghttp3）。`http_version="3"` 就走 H3，
服务端不支持时自动回退到 H2 / TLS；想要「不回退」用 `"3only"`（不支持直接报错）。

```python
# http_version 的字符串写法与数字写法完全等价，填哪一种都行：
#   "1.0" = 10    "1.1" = 11    "2" = 20    "2.0" = 20    "3" = 30    "3.0" = 30
r = nb_curl.get("https://h3.xcctls.top/h3_data", impersonate="chrome152", http_version="3")
print(r.status_code, r.http_version)      # 200 3
```

想确认某条连接是否**真的**走了 HTTP/3、并查看这条连接的详细信息，访问
[https://h3.xcctls.top/h3_data](https://h3.xcctls.top/h3_data)。

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

**Q：超时、请求头写错、域名解析不了……怎么全都报 `proxy handshake error`（curl 97）？**
因为 97 是**代理握手失败**，而握手发生在请求发出之前 —— 后面那些问题还没轮到就被它盖住了。
换句话说：不是报错不准，是每次请求都倒在代理那一步。看报错文案补的两行即可定位：

```text
proxy handshake error (curl 97 CURLE_PROXY，…)
  代理子原因 2 CURLPX_BAD_VERSION，对端回的版本号不是 SOCKS4/5，该端口多半不是代理或代理类型配错了
  本次请求走了代理 ALL_PROXY=socks5://127.0.0.1:1080；若不是本意，传 proxy="" 显式禁用，…
```

常见原因是代理地址写错、协议配错（把 HTTP 代理当 SOCKS 用），或环境变量
`http_proxy` / `https_proxy` / `all_proxy` 里留了个失效的代理。不想走代理就传
`proxy=""`（空串 = 显式禁用，连环境变量也不看）。

顺带一个容易踩的点：Windows 上 `HTTPS_PROXY` 与 `https_proxy` 会被当成两条记录各存一份，
而 `os.environ.pop("https_proxy")` 只会删掉其中一条 —— 想彻底清掉就得两种大小写各删一次，
否则会出现「Python 里删干净了、请求却还在走代理」。最省事的办法仍是直接传 `proxy=""`。

---

## 想自己编 C 内核？（可选，普通用户不用看）

wheel 里已经带好了编译好的 C 内核，**pip 装完就能用**。如果你要从源码重建它，
重建所需的材料都在 [`c_src/`](c_src/) 里：

| 目录 | 内容 |
| --- | --- |
| `c_src/patches/` | 上游依赖的补丁链 + 本项目增量补丁 `nb_curl.patch` |
| `c_src/native/` | C 桥接层源码 `nb_curl_bridge.c` / `.h` |
| `c_src/build/` | 构建脚本（Windows / Linux / Docker）、取源脚本、CFFI 构建脚本 |

具体说明见 [`c_src/README.md`](c_src/README.md)。

---

## License

本项目采用 **[MIT License](LICENSE)**。

需要说明的是：本仓库发布的 wheel 里**静态链接了以下第三方组件**，使用 / 再分发时请一并遵守它们的许可：

- **curl**（MIT/X 风格）
- **BoringSSL**（ISC + OpenSSL 双许可）
- **nghttp2**（MIT）
- **ngtcp2** / **nghttp3**（MIT，HTTP/3 的传输层与帧层）
- **curl-impersonate**（MIT）

---

## 致谢

- 指纹内核来自 [curl-impersonate](https://github.com/lwthiker/curl-impersonate)。
- 反指纹效果的可视化检测由 [xcctls](https://www.xcctls.top/) 提供：[/score 打分](https://www.xcctls.top/score) · [/all 指纹查看](https://www.xcctls.top/all)。
