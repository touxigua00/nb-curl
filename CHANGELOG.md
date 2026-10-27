# 更新日志

nb-curl 的版本变更记录。

## 版本与命名约定

- **版本号不随每次改动上升**。只有在明确要求升级版本时才升一次；中间的每一次交付
  都用「版本号 + 日期」归档，同一天有多次交付就再加序号：
  `release/v0.3.0-20260924/`、`release/v0.3.0-20260924-2/`、`release/v0.3.0-20260924-3/`……
- 本文件按**版本**记录。同一个版本号下的多次交付，改动都归入该版本条目，不另开新版本号。
- 归档规则只影响 `release/` 目录的命名，PyPI 上仍是标准版本号
  （`pip install nb-curl==0.3.2`）。

> **发布状态**：`0.3.2` 是当前版本；`0.3.1` 是上一版（Windows x64 + Linux x86_64 轮子）。
> `0.3.0` 汇总了 `0.2.2` 之后的**全部**改动 —— 期间版本号曾一个个往上加
> （`0.3.1`…`0.3.9`、`0.4.0`、`0.5.0`），涨得过快，已把这些中间版本全部折叠回 `0.3.0`，
> 因此本文件里的 `[0.3.0]` 条目覆盖的是 `0.2.2` 之后到 `0.3.0` 为止的改动。
>
> 早于 `0.2.2` 的条目保留在文件末尾，仅作历史。

## [0.3.2] - 2026-10-26

**本版主题：H3 补齐 `trust_anchors` / H2 帧级自定义 / path 转义保真。**

> 0.3.2 = 上一轮（10-26 白天）的 header_order 一等参数 + H3 指纹结构对齐 + path 转义，
> 加上本轮的 **QUIC 侧 `trust_anchors(51764)`** 与 **`diy_fp={"http2_frames": …}`**。
> 逐项都有「真机 Chrome 155」的前后对比实测，
> 复现脚本在 `reports/gap-audit-2026/`（`verify_fixes.py` / `quic_align_probe.py` / `quic_variance.py`）。

### 新增

- **`diy_fp={"http2_frames": …}`：HTTP/2 帧整体可自定义**（SETTINGS / WINDOW_UPDATE /
  PRIORITY / 伪头顺序），两种写法等价：
  - 字符串：`"1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"`
    （`SETTINGS|WINDOW_UPDATE|PRIORITY|ORDER`，与 `akamai=` 参数同格式；第 3 段
    写 `0` = 不发 PRIORITY 帧，也可以给 `"1:0:0:201"` 这样的规格）；
  - 字典：`{"settings": {"HEADER_TABLE_SIZE": 65536, "ENABLE_PUSH": 0, …},
    "window_updates": {"0": 15663105}, "order": "m,a,s,p"}`，可选第 4 个键 `priority`。
    `settings` 也收 `"1:65536;2:0"` 字符串；键可以是名字（大小写不敏感）或裸 id，
    **按写入顺序**发出（条目顺序本身也是指纹的一部分）。`window_updates` 只支持
    连接级（流 0）；`order` 收 `"m,a,s,p"` / `"masp"` / `["m","a","s","p"]`。
  取值范围即时校验（未知设置名、非连接级窗口、段数不对都会抛 `FingerprintError`，
  不会静默忽略）。与 H2 的既有单键（`http2_stream_weight` / `http2_headers_priority` /
  `http2_no_priority`）可以一起用，互不覆盖。帧级断言见
  `tests/test_protocols.py::http2.frames_custom`（读服务端收到的原始字节）。
- **`header_order=` 提升为与 `impersonate` 同级的一等参数**（会话级 + 请求级都收）：
  `"Host,Connection,sec-ch-ua,..."` 字符串或 `["Host","Connection",...]` 列表；大小写不敏感、
  重复名只留第一个、`Host` 强制第一位；名单内的头按序排最前、名单外的保持原相对顺序追加在后。
  不传 = 跟随预设；给了就**压过预设与 `diy_fp={"header_order": …}`**。
  实现复用已有的 `CURLOPT_HTTPHEADER_ORDER` 覆盖，不必再绕 `diy_fp`。
  用途：按资源类型切模板（Chrome 的导航与子资源是**两套**头序，见 `docs/17` §2.2）。
- **`http3_permute_extensions=`**：QUIC ClientHello 的 TLS 扩展顺序是否逐连接随机。
  不传时 Chrome / Edge 系预设**默认开**（与真机一致：Chrome 155 连抓 3 次得 3 种顺序）。

### 修复

- **QUIC ClientHello 补上 `0xca34`（`trust_anchors`, 51764, 186B）**（C 层，需重编
  `deps/windows-prebuilt/curl-impersonate`）：根因不是 BoringSSL 抑制，而是
  `http3_tls_extension_order` 这份显式顺序表**同时是白名单** —— 不在名单里的扩展一律
  不发，而列表里只写了 `0-10-13-16-27-43-45-51-57-17613-65037`，51764 没写进去。
  现在**只给 `chrome155` 补上 51764**（位置在 ALPS 与 ECH 之间），它的 QUIC ClientHello
  扩展数 10 → **11**，与真机一致。为什么不是四个预设都加：`trust_anchors` 这个扩展
  **Chrome 152 起才有**（仓库里 2026-09 的抓包可对账：真机 Chrome 150 的 ClientHello
  里没有 51764，Chrome 152 / 155 都有），`chrome145` / `chrome146` / `chrome150` 不该在
  画像里宣称自己发它 —— 它们也没配信任锚列表，所以就算写了今天也发不出去，但那只是
  "靠巧合正确"：哪天谁给它们配上锚，就会变成一条真机不存在的指纹。Firefox 从不发这个扩展。
  `CURLOPT_TLS_TRUST_ANCHORS` 的载荷（28 项、排序后 186B）本来就是对的，之前只是没被发出来。
- **HTTP/3 指纹结构对齐**（C/构建层，需重编 `deps/windows-prebuilt/{ngtcp2,nghttp3,curl-impersonate}`）：
  - `deps/patches/ngtcp2.patch` 此前从未真正编译进库 → 现已在 `deps/sources/ngtcp2-src` 落地并重建，
    恢复 `ngtcp2_conn_set_local_transport_params_raw()`；curl 侧重新接上预设的
    `CURLOPT_QUIC_TRANSPORT_PARAMETERS` 原始字节。于是 QUIC 的 **transport parameter 顺序、
    随机 GREASE TP、`0x3127/0x3128`、`version_information` 尾巴** 都与预设一致
    （此前被 ngtcp2 按自己的规范顺序重编码、未知 TP 全丢，每次连接逐字节同构）。
  - QUIC Initial 数据报 **1200B → 1250B**（`NGTCP2_MAX_UDP_PAYLOAD_SIZE`，与 Chrome 实测一致）。
  - QUIC ClientHello 的**扩展顺序逐连接随机**（`openssl.c`：QUIC 下装了显式顺序表时
    BoringSSL 的 permute 不生效，改成自己按 Fisher-Yates 洗一次，每个 SSL_CTX 一次 = 每条连接一次）。
- **path 里的 `%XX` 不再被强制大写**（`lib/urlapi.c` 两处：`Curl_parse` 的 URL 规范化 + `curl_url_set`）：
  `/a/%7euser` 现在与 Chrome 一样原样发出（此前会变成 `/a/%7Euser`）。
  对**签名字段含 path 原串**的接口是硬需求。

### 结论（不是 bug）：ECH GREASE 的长度是随机的，282 与 250 同源

上一轮把「QUIC 282B vs TCP 250B」记成了遗留项。本轮核对后确认**两边本来就是同一套随机**：

- BoringSSL `setup_ech_grease()`（`ssl/encrypted_client_hello.cc`）里
  `payload_len = 32 × 随机{4,5,6,7} + aead_overhead(16)`，扩展体 = `payload_len + 42`，
  所以整段只可能是 **186 / 218 / 250 / 282** 四种之一，每条连接重抽；
- 本机 8 份真机 Chrome 抓包（`_archive/tls-analysis/` + `tools_diag/`）里
  Chrome 实际出现过 payload **144 / 176 / 208 / 240**（四种全中，即上面四种长度全中）；
- 因此 250 与 282 的差异是**单次抽样差异**，不是 QUIC/TCP 两条路径分叉。

不改代码去「钉死」这个长度：Chrome 自己在变，钉死反而更假。

### 构建

- **CFFI 扩展的 include 目录指向了 9 月遗留副本**（`nb_curl/_cffi_build.py` /
  `c_src/build/_cffi_build.py`）：之前用 `<项目根>/native/`，那里的 `nb_curl_bridge.h`
  停在 9 月，缺 `nb_poll_item` / `nb_sock_info`，于是 `cl` 报一堆看不懂的语法错误
  （`error C2143` / `C2061`）而不是缺符号。现在优先用真身 `<项目根>/c_src/native/`，
  只在它不存在时回退旧路径。
- 重建流程（本轮实际跑过的顺序）：
  `build/windows/repack_curl_tar.sh`（把工作区改回收进源码包）→
  `rebuild_curl.sh` → `build_all.sh`（native DLL + CFFI）→ `build_wheel.sh`。
  **Git Bash 下调用 `cl.exe` 要先 `export MSYS2_ARG_CONV_EXCL='*'`**，否则 `/nologo`
  这类开关会被 MSYS 改写成路径、编译出来的 DLL 全是乱的（本轮踩过）。
- **Linux 轮子已重出**（manylinux_2_28，13.9 MB）：在构建机上的 `manylinux_2_28_x86_64`
  容器里编（`build-linux/scripts/15_quic.sh` + `20_curl.sh` → `manylinux/build_bridge.sh` →
  `build_cffi_linux.py` → `pip wheel` → `auditwheel repair`），BoringSSL/nghttp2 复用已有
  prefix（同一个源码归档，哈希一致），只有 ngtcp2/nghttp3/curl 重编。产物
  `nb_curl-0.3.2-py3-none-manylinux_2_28_x86_64.whl`，`.so` 的 GLIBC 符号上限 **2.28**
  （Ubuntu 22.04+ / Debian 12+ / RHEL 9+ 可用）。

### 验证

| 套件 | 结果 |
| --- | --- |
| `tests/run_local_regression.py` | **264 条全过** |
| `tests/test_browser_parity.py` | **64 条全过** |
| `tests/test_parity_edges.py` | **33 条全过** |
| `tests/test_stream_metadata.py` | **54 条全过** |
| `tests/test_protocols.py` | **94 条全过**（cffi 与 ctypes 各跑一遍；新增 `http2.frames_custom` 16 条） |
| `tests/test_async_protocols.py` | 21 过 / 1 失败（`h2.multi_concurrent_8`，与 0.3.1 基线同样失败，属既有多路复用缺口）/ 1 blocked（缺 `aioquic`） |
| `tests/test_socket_changes.py` | **7 个用例全过** |

QUIC 侧实测（`reports/gap-audit-2026/quiccap.py` 解 Initial，连抓 3 条连接）：
`chrome155` 扩展数 **10 → 11**、`0xca34` 长度 **186B** 每次都在、扩展顺序每条连接都不同
（`chrome145` / `chrome146` / `chrome150` 仍是 10 个扩展、没有 `0xca34`，与真机一致）；
ECH GREASE 在同一批抓包里出现了 **282 / 186 / 218** 三种长度（我们自己也在随机），
与 Chrome 的分布一致。

### 已知遗留（仍未做）

- QUIC 的 **GREASE 扩展**：`openssl.c` 对 QUIC 关掉了 `SSL_CTX_set_grease_enabled`
  （curl-impersonate 的老决定）。真机 Chrome 155 的 QUIC ClientHello 抓包里也没看到
  GREASE 扩展值，所以暂按"与真机一致"处理；哪天抓到 Chrome 在 H3 上带 GREASE，
  这里要重新打开（`if(peer->transport == TRNSPRT_QUIC) ... 0`）。
- QUIC 的 `version_information` 尾巴、GREASE TP 的**取值**每连接随机（Chrome 也随机），
  但我们的随机源是 ngtcp2 的 `Curl_rand`，与 Chrome 的分布没有做过逐值比对。

### 发布轮补充（2026-10-27，同一版本号的第二次交付）

本轮只动文档与打包，**API 与网络行为零改动**（三个平台的轮子源码 AST 与上轮完全一致）。

- **CFFI 扩展改名成稳定 ABI**：`_nb_curl_cffi.pyd`（Windows）/ `_nb_curl_cffi.abi3.so`（Linux），
  名字里不再带 `cp311`。cffi 默认就按 `py_limited_api` 编译（Windows 只导入 `python3.dll`，
  Linux 只引用 12 个 stable-ABI 符号），旧名字让 import 机制只在 3.11 上认它，
  3.12+ 白回退 ctypes。改名后**同一份产物覆盖 3.9~3.14**，不必按版本各编一次。
  实测：3.11 编的 `.pyd` 在 3.14 上、cp311 编的 `.abi3.so` 在 3.12 上都是 `backend=cffi`，
  264 条回归全过。
- **Windows 轮子补上 LICENSE**：`pyproject.toml` 改用 PEP 639（`license = "MIT"` +
  `license-files = ["LICENSE"]`，`setuptools>=77`）。此前 win 的 `dist-info` 里只有
  `License: MIT`、没有许可全文，linux 那份却有 —— 同版本两个轮子元数据不一致。
  同时 `build_wheel.sh` 的暂存步骤补上 `LICENSE`（原来只拷了 README/pyproject/setup.py）。
- **Linux 轮子瘦身**：桥接层链接加 `-Wl,--strip-debug`。`-g0` 只管自己那个 obj，
  `libssl.a` / `libcrypto.a` / `ngtcp2` 等静态库成员里的 `.debug_*` 段会被整段链进 `.so`：
  `libnb_curl_native.so` **37 MB → 5.0 MB**，wheel **13.9 MB → 3.6 MB**。
- **两个轮子现在用同一份"发布版"源码**：win 一直走 `make_release.py`（去解释性注释、
  保留 API docstring），linux 之前是直接在源码树上 `python -m build`，于是两边 `.py`
  内容不同。本轮统一为"Windows 暂存目录 → 同步到 Linux → 两边各自打 wheel"，
  两个轮子里的 `.py` 逐字节相同。
- **README**：删掉 `trust_anchors`（51764）小节；`header_order` 改成两种写法各一例
  （`diy_fp={"header_order": …}` 与顶层 `header_order=`）。

### 验证（2026-10-27 发布轮，两个轮子都重打后实跑）

| 套件 | Windows 轮子 | Linux 轮子 |
| --- | --- | --- |
| `tests/run_local_regression.py` | **264/264**（py3.11 + py3.14，均 `backend=cffi`） | **264/264**（宿主 py3.12 + 容器 cp311，均 `backend=cffi`） |
| `tests/test_parity_edges.py` | 33/33 | 31/32 —— 唯一失败 `partial.body.error_keeps_read` 是**既有的偶发竞态**（旧轮子同样复现，3 次里 1 次），与本次改动无关 |
| `tests/test_protocols.py` | 5/5（其余 blocked：缺 `h2`/`cryptography` 测试依赖） | 通过（H3 项 NOT-COVERED：无本地 H3 服务端） |
| 冒烟（真实站点 `chrome155`） | ja4 `t13d1517h2_8daaf6152771_cb7bf5808d99`；H2/stream/async/cookie/WS/自定义 ja3/`http2_frames`/`tls_trust_anchors`/`header_order` 两种写法全通 | 同一 ja4，逐项同样通过 |
| 打包校验 | `twine check` PASSED；`License-File` + `dist-info/licenses/LICENSE`；`.pyd` 无版本段 | `twine check` PASSED；RECORD 39 行无 mismatch；`License-File` 有；`.abi3.so`；GLIBC 上限 2.28 |

体积：win 轮子 **1.87 MB**；linux 轮子 **3.61 MB**（上一轮 13.94 MB）。

## [0.3.1] - 2026-10-23（HTTP 报文口径对齐 Chrome 155）

**唯一标准是本机真机 Chrome 155.0.8059.85**（37 个 fetch/表单/iframe 场景 + 方法×3xx 矩阵 +
h2 抓包 + 语义追问，见 `docs/16-curl_cffi修复对照审计.md` 第 10 节）。
凡浏览器做不到的（重复请求头、GET 带 body、非 ISO-8859-1 头值）我们也不做；凡浏览器会做的
（同名头 ", " 合并、URL 自动转义、303 全降级 GET、cookie 创建序…）我们就照做。

### 变更（破坏性）

- **同名请求头合并成一条**：`headers=[("X","1"),("X","2")]` 与 `{"X": ["1","2"]}` 都发 `X: 1, 2`。
  实测 Chrome 155 根本发不出两行同名请求头（fetch 数组形式与 XHR 两次 setRequestHeader 都是 ", " 拼接）。
- **URL 永远自动转义**（空格→`%20`，中文→`%E4%B8%AD`，已有 `%XX` 不动），与地址栏一致；
  以前这种 URL 直接报 `curl 3 CURLE_URL_MALFORMAT`。没有 `quote=` 开关（浏览器也没有）。
- **GET/HEAD 带 body 直接抛 `TypeError`**（Chrome：`Request with GET/HEAD method cannot have body`）。
- **非 ISO-8859-1 头值抛 `TypeError`**（Chrome fetch/XHR 同样抛），不再静默发 UTF-8 字节。
- **Content-Type 推断按浏览器**：`data=str` → `text/plain;charset=UTF-8`；二进制 → **不发**；
  `data=dict` → `application/x-www-form-urlencoded`（表单提交口径，**不带** charset）；
  无 body → 不发；`files=` → `multipart/form-data; boundary=----WebKitFormBoundary…`。
- **响应头名字保持服务端原样**：`r.headers.keys() / items() / to_dict()` 用服务端给的原始大小写
  （`Content-Type` 就是 `Content-Type`），重复值按 `", "` 合并；按名取值一直大小写不敏感。
  浏览器的 `Headers` 会统一小写展示 —— 这一条**有意不同**：不改写用户看到的东西。
- **删掉 6 个"浏览器里不存在"的 API**：`quote=`、`default_encoding=`、`raise_for_status=`、
  `Response.is_redirect`、`cookies.set(...)`、`cookies.get_dict(...)`。
  cookie 携带策略改用浏览器的 **`credentials="omit"`**（原 `discard_cookies=` 删除）。

### 修复

- **重定向方法矩阵与浏览器一致**（5 个方法 × 5 个 3xx 全实测）：301/302 只把 POST 降级为 GET；
  303 除 HEAD 外全部降级为 GET（PUT/PATCH/DELETE 也是）；307/308 保留方法与 body。
  POST/GET/HEAD 走 libcurl 原生语义；其余方法的 303 由 Python 侧逐跳跟（`history` / `redirect_count` 照常）。
- **cookie 顺序**：创建序 + 长 path 在前（RFC 6265 5.4 / Chrome 实测）；同名不同 path 全都发。
- **cookie 作用域**：`session.cookies[k]=v` 首次请求时绑到该主机（host-only），不跨站；
  `Domain=` 不匹配拒收；`Secure` 只在安全上下文发（`https` / `localhost` / `127.0.0.1`，Chrome 同此）。
- **cookie 删除**：`Max-Age=0` / 过期 `Expires` 罐里与线上同步删除（以前留"幽灵 cookie"）。
- **HTTP/2 上 Cookie 仍是**一条**头**（实测 Chrome 155 不拆行；上一版按"Chrome 会拆"实现是错的，已撤）。
- **尊重 `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE`**。
- **`json()` 先按 UTF-8 解**，解不开才回退声明的 charset（Chrome 对 `application/json; charset=gbk`
  会直接乱码，我们在这点上故意比它宽容）。

### 构建

- `build/windows/build_native.sh` 改指 `c_src/native/nb_curl_bridge.c`（仓库里 C 源码的真身；
  `python/native/` 是 9 月的残留副本，不参与构建）。

### 验证

- 新增 `tests/test_browser_parity.py`（64 条断言，期望值全部来自真机 Chrome 抓包）。
- 全量 492 条断言全绿：`run_local_regression` 264 + `test_browser_parity` 64 +
  `test_parity_edges` 33 + `test_stream_metadata` 54 + `test_protocols` 77。

### 已知差异（等你定）

- `Origin` / `Referer` / `Cache-Control: max-age=0` / `Sec-Fetch-User` 这类头取决于**发起上下文**
  （有没有来源页、是不是用户激活、是不是刷新）。我们的请求没有来源页，浏览器里没有等价场景，
  所以暂不发；要补得先定义"我们的请求等价于浏览器的哪种发起方式"。
- Linux wheel 需用同一份源码重出包。

## [0.3.1] - 2026-10-15

本版把执行层整体换掉（同步 / 异步 / 流式统一由 libcurl multi 驱动托管），高并发吞吐与资源占用
明显改善；并按本机真实 **Chrome 155** 校正了内置预设。**`chrome152` 预设已删除。**

### 变更（破坏性）

- **预设 `chrome152` 改名为 `chrome155`，旧名字直接删除**（传 `chrome152` 会抛 `ImpersonateError`）。
  该预设的 TLS 层本来就与当前 Chrome 一致（ja4、密码套件、曲线、签名算法、扩展集合、
  `trust_anchors(51764)` 的 186 字节载荷全同），只有 `sec-ch-ua` / `User-Agent` / `Accept`
  三个请求头停在旧抓包上。本版按真实 **Chrome 155.0.8059.80** 校正为
  `sec-ch-ua: "Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"`、
  `Chrome/155.0.0.0`、`Accept` 补上 `image/jxl`；家族别名（`chrome` / `chromium`）指向 `chrome155`。
- **桥接层 ABI 升到 v3**（`nb_multi_abi_version() == 3`）：Python 侧两个后端在导入时强校验版本，
  与 `nb_curl/_lib/` 下的动态库 / CFFI 扩展不匹配会直接报错，**不静默回退**。升级时请一并更新两者。

### 新增

- **`diy_fp={"header_order": ...}` 支持列表**：字符串与 list 两种写法等价
  （`"a,b"` 与 `["a", "b"]`），并且 **`host` 永远排在第一位** —— 名单里没写会自动补在最前，
  写在别处会被提上来，重复项只留一份。未列出的头保持原相对顺序追加在后，HTTP/1.1 与 HTTP/2 都生效。
  （它只负责排序，名单里的头必须真的在请求里存在。）
- **`trust_anchors`(51764) 可以单独设置**：`diy_fp={"tls_trust_anchors": "..."}` 整份替换预设的 28 项；
  空串 `""` 表示显式发送空列表（线格式 `0000`，与"扩展不存在"不是一回事）；不配预设也能单独发。

### 改进

- **异步非流式不再"每请求一个线程"**：改为 libcurl multi 驱动（Windows 用有界专职驱动线程，
  POSIX 直接挂在调用方事件循环上，可用 `NB_CURL_ASYNC_DRIVER=thread|loop` 覆盖）；流式请求由
  会话级 reactor 驱动，异步流同样支持同步的 `response.content` / `iter_content()`，不会与调用方
  事件循环互相死锁。
- **高并发吞吐**（同机回环、HTTP/1.1 keepalive、128 字节响应、`AsyncSession` 单会话，
  每格 5 次重复全部通过才计入）：并发 128 从 3,689 → **7,102 req/s**，并发 512 从 2,355 → **7,133 req/s**；
  并发 512 时每成功请求的客户端 CPU 从 0.44 → 0.14 ms、p95 从 239 → 92 ms。低并发（1）基本持平。
- 连接池空闲句柄 O(1) 获取；非流式结果从 C 累积缓冲**直接移交**所有权（少一次整块拷贝）；
  `timeout` / `connect_timeout` / `auth` / `ech` 从"有值"切到"无值"时显式复位（旧实现会残留到下一次请求）；
  连接分区把 `proxy=None`（跟随环境变量）与 `proxy=""`（显式禁用）分开。

### 修复

- **报错文案统一单行**（回归用例 `errors.one_line`）：以前 97 / 52 这类错误的附加信息
  （`代理子原因 …`、`本次请求走了代理 …`）会另起一行并缩进两格，日志里一行 ERROR 被撑成
  三行，"一大坨"把上下文挤走。现在这些信息改用 `；` 接在同一行（细节一个字没删，
  错误码手册链接仍在），并对 libcurl 原始信息里残留的 CR/LF / 连续空白做折叠 ——
  `str(exc)` 保证不含换行。
- **WebSocket 对端不发 CLOSE 直接断开时不再抛 `NameError`**：`ws.py` 用了没有导入的
  `CURLE_GOT_NOTHING`，该分支现在按文档语义返回 `None`（`recv()` 视为连接已结束）。
- **`AsyncSession.close()` 的"补一次有界等待"真正生效**：`aio.py` 引用了未定义的
  `_STREAM_REACTOR_GRACE`，异常被 `except Exception` 吞掉，等于没有这一步；
  现从 `session` 导入该常量（5.0 秒），与 `Session.close()` 的等待预算一致。
- **`diy_fp={"http2_headers_priority": ...}` 不再被静默忽略**：`parse_diy_fp` 漏了赋值，
  传 `True` / `False` 都没有效果；现在按预期下发。与 `http2_no_priority=True` 同时给时会在
  请求发出前抛 `FingerprintError`（互斥校验本来就有，之前因为字段永远没被赋值而触发不到）。
- **`curl_options` 的取值说明与报错文案改掉误导写法**：`nb_curl.options` 这个名字在本包里是
  HTTP 的 OPTIONS **函数**（requests 习惯，遮蔽了同名子模块），原来的
  `nb_curl.options.SAFE_OPTIONS` 取不到；文档与 `ValueError` 文案统一改为
  `nb_curl.CurlOpt` / `from nb_curl.options import ...`。**公开 API 未变。**
- **取值范围自省的条目数对齐实际**：`tls.supported_ciphers()` 的说明由"37 个"改为 **34 个**
  （37 是含 TLS1.3 的联合表条数），`tls.supported_extensions()` 由"31 个"改为 **32 个**。
- **显式给的 cookie 不再被重排**（回归用例 `cookies.order`）：以前
  `headers={"Cookie": "uin=; p_uin=; p_uid=; TRACE=…"}` 和 `cookies={...}` 都只是把 cookie
  塞进 libcurl 的 cookie 引擎，而引擎在拼请求头之前会按
  `path 长度 > domain 长度 > name 长度 > 创建时间` 重排（`lib/cookie.c: cookie_sort`），
  线上就成了 `Cookie: TRACE=…; p_uid=; p_uin=; uin=` —— 按 cookie 出现顺序校验的站点直接判失败。
  现在显式 cookie 由 `CookieJar.header_value()` 按**给进来的顺序**拼成一条 `Cookie: …` 头
  （会话罐里命中该主机 / 路径 / `Secure` 作用域的 cookie 按罐内顺序跟在后面，同名不重复），
  此时 cookie 引擎本次清空静默（仍照常记录响应的 `Set-Cookie`，临时 cookie 依旧不进会话罐）。
- **`Cookie` 头只发一条、值逐字节原样、位置跟着 `headers=` 走**（回归用例 `cookies.order`
  与 `http2.cookie_header`）：
  - **一条**：curl-impersonate 的每个预设都开着 `split_cookies`，HTTP/2 下 libcurl 会把
    `Cookie: a=1; b=2` 拆成两条 `cookie` 头（`lib/http.c` 的 `http_cookies` split 分支）。
    按 RFC 9113 §8.2.3 接收方应当用 `"; "` 拼回去，但现实里大量服务端/中间件按"同名头覆盖"
    处理，整串登录态只剩最后一条。本版把 `CURLOPT_SPLIT_COOKIES` 默认置 0，cookie 永远一条头。
    这条**只影响引擎那一路**（会话罐）：显式 `Cookie` 头本来就是一条真实 header 行，不走引擎。
  - **原样**：显式串不再"解析成 pairs 再拼回"，多余空格、重复名、空值（`uin=`）、
    大小写、末尾分号都不改写（只有行首尾空白按 HTTP 语义去掉）。
  - **位置**：以前显式 cookie 走 `CURLOPT_COOKIE`，那是 libcurl 自己在 header 块里**补**一条
    `Cookie:`（`http_cookies()` 写在自定义头之前），所以永远排在 Host 之后第一条，
    `headers=` 里的位置完全无效。现在它就是 `headers` 里的一条普通行 ——
    写在最后就发在最后；只给 `cookies=` 时追加在用户头的末尾。
  - 想要浏览器式拆行（Firefox 在 h2 上就是一条 cookie 一对）仍可显式打开：
    `diy_fp={"split_cookies": True}`（作用于引擎/会话罐那一路）。

### 验证

- 本机回归：两个 FFI 后端（cffi / ctypes）× 15 个套件全部通过，含协议、HTTP/3、平价边界、
  流式元数据与 6 个 smoke 套件；指纹评分与真机 Chrome 155 逐项对齐（第三方检测站 95 / 100，
  与 `0.3.0` 相同，扣分项仍是 ECH 一项）。
- 上述修复后重跑 `tests/run_local_regression.py`（cffi 后端、262 项断言）：**262 通过 / 0 失败**；
  `tests/test_protocols.py --only http2`（含新增 `http2.cookie_header`）在 cffi / ctypes 两个后端
  上均全绿。

## [0.3.0] - 2026-09-24

本条目覆盖 `0.2.2` 之后的所有改动：HTTP/3、ECH、WebSocket、`curl_options` 直通、
TCP 层画像（JA4T）、参数说明模块，以及一次公开接口的参数声明方式重构。

### 变更（破坏性）

- **公开入口的参数声明方式更换**。原先 `get` / `post` / … 每个方法都把 35 个参数逐个罗列
  一遍（8 个方法抄 8 遍），现在改为用类型化的参数字典整体展开，参数声明只有一处。
  对使用者的实际影响有三点：

  1. **`inspect.signature()` 的结果变了**。如果你的代码做了运行时参数反射（依签名判断能传
     哪些参数），需要改成查 `nb_curl.params` 的键集合。
  2. **传错的参数名会立刻报 `TypeError`**（并给出最接近的合法名建议）。以前多写一个字母或
     写错名字会被静默忽略、请求照发，现在会在发请求前就拦住。这是最容易「升级后才发现」的一点。
  3. **IDE 补全取决于版本**：PyCharm 2024.1+ 与 VS Code（Pylance）可正常补全参数名、显示
     悬停文档；更早的 IDE 只显示 `**options`，但运行行为不受影响。

- **TCP 层画像（JA4T）的最终形态是「socket 级、跨平台、且绝不改本机默认窗口」**。
  这个能力经历了几轮反复，现在的语义即最终语义（旧写法已全部失效）：

  请求级 `tcp=` 接受**完整的 JA4T 值**（如 `"64240_2-1-3-1-1-4_1400_8"`，四段都填真实值），
  也接受只给关心字段的 dict（如 `tcp={"window": 64240, "wscale": 8}`）。
  可改的观测点：`ttl`（也可用独立参数 `ttl=`）、`mss`、`window` + `wscale`。
  曾经存在过的旧版 TCP 接口（独立子模块、`tcp_fp()`、`[tcp]` 安装扩展与随之引入的
  第三方依赖、`set_interface_mtu()` / `set_tcp_timestamps()` 等）**都已删除**，传了会报
  `TypeError`。

- **DNS 解析能力（`dns=`）已整体移除**。`nb_curl.dns` 子模块、`nb_curl.dns_servers()`、
  `Session(dns=...)` / `prefetch_dns=...` 全部删除，没有替代接口。
  需要钉住解析结果时，用 curl 原生的 `resolve=`，或配合 `doh=`。

### 新增

- **HTTP/3**：`http_version="3"` / `"3.0"` / `"3only"`。底层集成 ngtcp2 + nghttp3
  （BoringSSL crypto 后端），内置浏览器预设可直接走 H3。

  ```python
  r = nb_curl.get(url, http_version="3")        # 不支持 H3 时自动回退 H2/TLS
  r = nb_curl.get(url, http_version=3.0)        # 数值写法等价
  r = nb_curl.get(url, http_version="3only")    # 强制 H3，不支持则报错
  r.http_version                                # '3'
  ```

  H3 侧发的是与浏览器一致的完整 `SETTINGS` 帧（内容与顺序均对齐，含随机 GREASE 条目）。
  TLS/H2 指纹不受影响。

- **ECH（Encrypted ClientHello）**：`ech=` 支持 `True`（="true"，尽力，需配合 `doh`）、
  `False`、`"grease"`、`"hard"`、`"ecl:<base64>"`、`"pn:<name>"`。
  自动模式靠 `doh` 从 HTTPS RR 取 ECHConfig。

- **WebSocket**：`Session.ws_connect(url)` 返回 `nb_curl.WebSocket`，支持
  `send` / `send_text`（别名 `send_str`）/ `send_bytes` / `ping` / `recv(timeout)` / `close`。
  自动处理 PING（回 PONG）/ CLOSE 帧，大帧分片重组。

- **`nb_curl.params` 参数说明模块**：所有参数的合法取值从此有出处可查。

  ```python
  import nb_curl

  print(nb_curl.params.describe())         # 全部参数一览（带取值说明）
  print(nb_curl.params.describe("tcp"))    # 只查一个参数，tcp / resolve / http_version 都行
  help(nb_curl.params.RequestOptions)      # 类型定义 + 逐项说明
  ```

  `tcp`、`resolve`、`http_version` 这类「知道能传字典、但不知道键怎么填」的参数，
  现在在源码里和 `describe()` 输出里都写明了键名、取值范围与示例。
  另有 `nb_curl.params.check_options()`，可用于在自己的代码里做参数前置校验。

- **HTTP/2 HEADERS 的优先级字段可开关**：`h2_priority=`（`True` / `False`，默认跟随所选
  指纹预设）。Chrome 系导航请求本来就带 RFC 7540 优先级字段（HEADERS flags `0x25`），
  需要「不带优先级」（flags `0x05`）时用 `h2_priority=False`。
  与 `diy_fp` 的 `http2_no_priority` 互斥，两个一起给会报 `FingerprintError`。

- **`curl_options` 直通**：`Session(curl_options={CurlOpt.X: value})`，329 个 `CURLOPT_*`
  全量暴露，按值类型自动分派（long / string / slist / off_t）；回调 / blob / 二进制指针类
  拒绝，破坏指纹或与专用参数冲突的项需 `allow_dangerous_options=True`。
  白名单见 `nb_curl.options.SAFE_OPTIONS`。

- **`resolve=` 支持**：`resolve={"host:port": "ip"}`（等价 curl `--resolve`，只影响本地解析；
  走 http/socks5h 代理时由代理解析，此项无效）。

- **DoH**：`doh="https://1.1.1.1/dns-query"`，ECH 自动模式的前置。

- **连接类选项**：`interface`（出口绑定）、`pinned_key`（证书固定）、
  `max_download_speed` / `max_upload_speed`（限速）。

- **cookie 持久化**：`Session.save_cookies(path)` / `load_cookies(path)`，
  Netscape jar 格式（curl 的 `CURLOPT_COOKIEFILE` 也能直接读）。

- **HTTP/1.1 下自动补齐 `Connection: keep-alive`**：使用内置浏览器预设发请求时，
  若请求里没有显式写 `Connection`，库会按真实浏览器的位置补上它（紧跟在 `Host` 之后）。
  HTTP/2 下不补（`Connection` 是 HTTP/2 的禁止字段）。关掉自动补齐写作
  `impersonate="chrome152:no"`。

- **TCP 层画像自省**：`nb_curl.tcp_support()` 报告本机每个观测点**能不能改、落点在哪、
  改完能不能回读证实**；`nb_curl.set_tcp_warnings(False)` 静音平台警告。

- `examples/trust_anchors_demo.py`：离线演示 `trust_anchors(51764)` 扩展的默认行为与自定义
  写法（用一个「只收不答」的本地监听截下自己发的第一条 ClientHello 再解扩展表，
  不需要证书、不连外网）。

- `CurlOpt`、`WebSocket`、`apply_curl_options` 在 `nb_curl` 顶层导出。

### 变更（行为）

- **默认窗口绝不被改动（Windows 与 Linux 一致）**：只要给出的 `window` / `wscale` 这一对
  **不能同时精确达成**，就完全不碰 `SO_RCVBUF`，本机默认窗口原样保留（Windows 上常见
  `64240`），只发一条警告说明哪一项做不到。不会再出现「设了 TCP 画像，默认窗口就从
  64240 变成 65535」这类副作用。
- **本机做不到的 TCP 项只发警告、不报错**，请求照发，只是该项不生效。静音方式：
  `nb_curl.set_tcp_warnings(False)`，或标准的
  `warnings.simplefilter("ignore", nb_curl.TCPShapeWarning)`。只有画像串本身写错
  （格式、类型、取值越界）才抛 `nb_curl.TCPShapeError`。
- **TCP option 顺序任何系统都改不了**（写在内核里，无 socket 接口），顺序段只能填本机原生值，
  否则发警告：Windows `2-1-3-1-1-4`、Linux `2-4-8-1-3`（关掉全局时间戳后变 `2-1-1-4-1-3`）。
- **MSS 的平台落点不同**：Linux 走 `TCP_MAXSEG` 逐 socket 生效（实测 `mss=1200` 时对端读到的
  MSS 就是 `1200`）；Windows 只能改网卡 MTU（`MSS = MTU - 40`，需管理员），
  且受路由 PMTU 限制。
- **模块级入口 `nb_curl.get(...)` / `nb_curl.post(...)` 现在也接受会话级参数**
  （`max_clients`、`allow_dangerous_options` 等），此前只能传给 `Session(...)`。
- `http_version` 接受 `"3"` / `"3.0"` / `"3only"`。

### 改进

- **`chrome152` 预设的 `trust_anchors(51764)` 扩展改为完整的 28 项信任锚 ID**，
  与 Chromium 的 `chrome_root_store/root_store.textproto` 里的 `trust_anchor_id` 一一对应。
  此前发的是 2 字节空列表 —— 这是一个与真实浏览器不一致的确定性特征，单看扩展长度即可识别。
  想改回空列表或显式指定，用 `diy_fp={"tls_trust_anchors": ...}`。
- **信任锚列表的排列改为「单次运行内固定、运行之间随机」**：此前是每条连接重新随机排列，
  同一进程的连续连接彼此顺序都不一样；真实 Chrome 在一次运行内保持同一顺序（实测 30 条连续
  连接字节完全相同），换一次运行才变。
- **报错带 curl 错误码 + 中文说明 + 官方手册链接**：异常统一带完整 CURLcode 信息，
  常见错误码（解析失败、连不上、超时、TLS 握手失败、证书校验失败、重定向超限等）配中文一句话
  说明，没收录的回退到符号名。`RequestError.code` / `.curl_name` 可编程判断：

  ```python
  try:
      r = s.get(url)
  except nb_curl.RequestError as e:
      e.code        # 56 —— CURLcode 数值
      e.curl_name   # 'CURLE_RECV_ERROR' —— 符号名
  ```

  错误码符号表从 curl.h 自动生成（`nb_curl._curle_generated.CurlE`），与所链接的
  libcurl 版本一致。
- **全部公开接口带类型标记**（`py.typed`，PEP 561），静态分析工具与 IDE 可正常解析；
  `AsyncSession` 改为顶层直接导入，不再靠 `__getattr__` 惰性转发。
- 参数声明从「8 份拷贝」收敛为 `params.py` 一处，新增 / 修改参数的成本从改 8 个方法变成改
  1 处，也不会再出现「某个方法漏抄了一个参数」这类不一致。
- 清理源码注释里的版本变更流水账（「vX.Y.Z 新增……详见某文档」这类）。

### 修复

- **Linux 上 `h2_priority=False` 之前不生效**（HEADERS 依旧带优先级字段），已修正。
- **HTTP/3 指纹此前未生效**：早期版本走 H3 时发的是 libcurl 默认的 `SETTINGS` 帧
  （3 条默认值、无 GREASE 条目），不带浏览器指纹。现在按浏览器真实值发送完整 `SETTINGS`。
- **`nb_curl.xcctls` 解析快照时不再把「没抓到 `trust_anchors` 载荷」当成「空列表」**：
  没有载荷就不覆盖该字段（沿用底座预设的列表）并给一条 `UserWarning`；有载荷时按线格式解码
  后回放。注意空列表的编码是 `0000`，与「没抓到」不同。
- **从 `Set-Cookie` 学到的 Cookie 会在 `Cookie` 请求头里出现两次**，已修正：
  Cookie 现在只由会话的 Cookie 罐统一输出一次；显式传入的 Cookie 行为不变。
- **`stream=True` 现在是真正的增量下载**。此前 `Response.iter_content()` /
  `iter_lines()` 是在已经整体缓冲好的响应体上做切片；现在边收边给，
  `iter_content()` 还能从中断处继续往后读，而 `Response.content` / `text` /
  `json()` 读取的是**尚未读走的剩余部分**。用完、或中途不再需要时请调用
  `Response.close()` 释放连接。
- **代理握手失败的报错不再只有一句 `proxy handshake error`**。以前只要代理那一步出问题，
  报错都是同一个 `curl 97 CURLE_PROXY`，超时、请求头写错、域名解析失败看起来全一个样，
  也看不出请求到底走了哪个代理。现在这类错误除了错误码与中文说明，还会补上
  **代理子原因**（`CURLPX_*`，见 libcurl 手册）和**本次实际使用的代理**（显式传入的以传入值为准，
  否则按 libcurl 的查找顺序报告生效的环境变量），并给出禁用办法。顺带两点：
  `CURLE_PROXY` 现在抛 `ProxyError`（`RequestError` 的子类，原有 `except RequestError` 不受影响）；
  判断环境变量代理时的查找顺序已对齐 libcurl（先 scheme 专属再看 `all_proxy`，http 只看小写
  `http_proxy`），实际生效的代理以 libcurl 读到的环境为准。
- 修正若干失效的文档引用与排版问题。

## [0.2.2] - 2026-09-12

### 新增

- **Linux x86_64 轮子**：从本版起同时提供 Windows x64 与 Linux x86_64 两个平台的预编译
  wheel，`pip install` 不需要编译器、不需要源码。

## 历史归档（`0.2.2` 之前）

以下条目仅作历史保留，不再维护。

## [0.2.1] - 2026-09-12

### 修复

- 并发场景下关闭 `Session` / `AsyncSession` 可能崩溃：连接池在关闭时会把仍在使用的句柄一并释放。
- `AsyncSession.close()` 改为异步方法，现在需要 `await session.close()`（或直接用 `async with`）。

## [0.2.0] - 2026-09-11

### 变更

- 项目改名：发行名 `nb-curl`、导入名 `nb_curl`。
- 首次发布到 PyPI。
- wheel 默认按"发布版"构建：去掉解释性注释和模块 docstring，保留类/函数/参数的 API 说明。

## [0.1.4] - 2026-09-11

### 新增

- 内置预设 `chrome152`（含签名算法 GREASE、空 trust_anchors 扩展）。
- `diy_fp` 新增两个键：`tls_grease_sigalgs`、`tls_trust_anchors`。
- `impersonate` 参数补全类型提示，IDE 里可直接列出全部内置预设。
- 统一代理参数的优先级：请求级 `proxy` > 请求级 `proxies` > 会话级 `proxy` > 会话级 `proxies`。

### 变更

- 移除 `extra_fp`，统一用 `diy_fp`（再传 `extra_fp` 会直接抛 `TypeError`）。

## [0.1.3] - 2026-09-11

### 新增

- `fp_file`：把指纹检测站 `/all` 的快照存成 JSON，一键复刻某台真实浏览器的完整指纹（含浏览器默认请求头）。
- `parse_xcctls()` / `load_fp_snapshot()`：快照解析与加载；也支持 `impersonate=` 直接传 `Fingerprint` 对象。

### 修复

- `parse_xcctls` / `load_fp_snapshot` / `diy_fp_fields` 在顶层声明了但从未导出，无法访问。
- `impersonate=` 传入 `Fingerprint` 对象时抛 `AttributeError`。
