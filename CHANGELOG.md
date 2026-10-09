# 更新日志

nb-curl 的版本变更记录。

## 版本与命名约定

- **版本号不随每次改动上升**。只有在明确要求升级版本时才升一次；中间的每一次交付
  都用「版本号 + 日期」归档，同一天有多次交付就再加序号：
  `release/v0.3.0-20260924/`、`release/v0.3.0-20260924-2/`、`release/v0.3.0-20260924-3/`……
- 本文件按**版本**记录。同一个版本号下的多次交付，改动都归入该版本条目，不另开新版本号。
- 归档规则只影响 `release/` 目录的命名，PyPI 上仍是标准版本号
  （`pip install nb-curl==0.3.0`）。

> **发布状态**：`0.2.2` 是线上基线，也是最后一版同时提供 Windows x64 与 Linux x86_64 轮子的版本。
>
> `0.3.0` 汇总了 `0.2.2` 之后的**全部**改动。期间版本号曾一个个往上加
> （`0.3.1`…`0.3.9`、`0.4.0`、`0.5.0`），涨得过快，现已把这些中间版本全部折叠回来 ——
> **`0.3.0` 就是当前版本，`0.2.2` 之后的每一条改动都能在本条目里找到。**
>
> 早于 `0.2.2` 的条目保留在文件末尾，仅作历史。

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
