# tests —— 本地回归套件

纯 stdlib，不打任何第三方站点，不涉及指纹/反检测；全部流量走 `127.0.0.1`
（端口动态绑定，套件结束会断言端口确实已释放）。

| 文件 | 说明 |
|---|---|
| `run_local_regression.py` | 回归套件本体（29 个用例 + 结束时追加的 `server.cleanup` / 240 条断言，同步 + 异步） |
| `test_protocols.py` | 协议层协商：本地 TLS 校验 / 错误 CA / 真实 HTTP/2 / WebSocket 收发 |
| `test_http3.py` | HTTP/3 普通功能（本地 aioquic H3 UDP 服务端，强制 `3only` 不降级） |
| `test_async_protocols.py` | `AsyncSession` 在同一个会话上的 multi 并发（H2 + H3）与流式行为 |
| `test_parity_edges.py` | 平价边界：认证残留、超时覆盖/复位、`resolve=`、`curl_options`、编码、deflate、短体 |
| `test_stream_metadata.py` | `stream=True` 的响应元信息（`url` / `headers` / `history` / `elapsed` / cookie） |
| `test_socket_changes.py` | socket 增量队列与 loop 注册（不连网，用假 loop 观测注册/注销） |
| `protocol_fixtures.py` | 测试用本地服务夹具：临时 CA + 叶子证书、TLS/H2/WebSocket 服务端 |
| `local_server.py` | 本地 HTTP/1.1 keepalive 测试服务（动态端口、可观测计数器、慢发/中断/RST 等端点） |

本文里的每个数字都是**本机实跑**出来的（Windows + Python 3.11 + cffi / ctypes 两个后端），
命令与结果都在下面，没有"没跑就先写实测"的条目。

---

## 1. 运行

在**仓库根目录**执行；被测实现由 `--package-path` 显式指定（`.` 即当前仓库）：

```bash
# 回归套件本体（同步 + 异步，240 条断言）
python tests/run_local_regression.py --package-path .

# 其余四个协议/元信息套件（都收 --backend）
python tests/test_protocols.py       --package-path . --backend cffi
python tests/test_http3.py           --package-path . --backend cffi
python tests/test_async_protocols.py --package-path . --backend cffi --protocol both
python tests/test_stream_metadata.py --package-path . --backend cffi
python tests/test_parity_edges.py    --package-path . --backend cffi

# socket 增量队列（不连网，不需要 --package-path）
python tests/test_socket_changes.py  --backend cffi
```

几个要点：

* **后端怎么选**：`run_local_regression.py` 没有 `--backend` 开关，用环境变量
  `NB_CURL_BACKEND=cffi|ctypes`（nb_curl 导入时读）；上面其余套件都直接收 `--backend`。
* **aioquic**：`test_http3.py` / `test_async_protocols.py` 需要 `aioquic`（H3 服务端）；
  装在当前解释器里即可，也可以用 `--aioquic-path <aioquic 所在目录>` 额外插一个搜索路径。
  缺 `aioquic` / `cryptography` / `h2`，或客户端 native 未编译 nghttp3 → 记 **blocked** 并退出 3。
* **也可以只靠 PYTHONPATH**（不传 `--package-path`）：

  ```bash
  set PYTHONPATH=. && python tests/run_local_regression.py        # Windows
  export PYTHONPATH=. && python tests/run_local_regression.py     # Linux / macOS
  ```

常用开关（`run_local_regression.py`）：

```
--package-path DIR   指定 nb_curl 所在目录（可多次给，第一个优先）
--only SUBSTR[,SUBSTR]   只跑名字含子串的用例
--list               列出用例后退出
--json PATH          写完整结果 JSON（含实现指纹、每条断言、用例耗时）
--utf8-output        把 stdout/stderr 切成 UTF-8（日志被管道/UTF-8 终端采集时用）
--fail-fast          首个失败用例后停止
--overall-timeout S  套件总时长上限（默认 900；到点打印横幅并以退出码 3 强制退出）
--host/--port        本地服务绑定（默认 127.0.0.1:0）
```

退出码：`0` 全部通过 / `1` 有断言失败 / `2` 环境不满足（import 不到、`--only` 无匹配）/ `3` 看门狗超时。

### 实现是怎么选中的

* 只认**显式**给出的目录（`--package-path` 或 `PYTHONPATH`）。套件自己只把
  `tests/` 目录加进 `sys.path`（为了 import 同级的 `local_server` / `protocol_fixtures`），
  不会插入任何其它路径。
* 导入后会核对 `nb_curl.__file__` 是否真落在指定目录内，不符立即 `SETUP FAIL` 退出（码 2）。
* 启动横幅会打印解析到的实现文件 / 版本 / 后端 / `backend_info`。
* 启动时会清掉进程内 `http_proxy/https_proxy/all_proxy/no_proxy`，**报告里只记变量名**
  （`proxy_env_scrubbed`）—— 这些值常写成 `http://user:password@host`，落盘就是泄漏凭证。
  清环境变量只是**防御**（宿主机的代理变量不该影响回环流量），不是 `proxy=""` 的替代：
  显式禁用代理（`proxy=""`，连环境变量都不读）是**必须保留的公开 API**，
  由 `proxy.empty_string` 用例专门盯着。

### 没有 skip

失败就是失败：没有 `skip`、没有 `xfail`。缺依赖记 `blocked` 并**非零退出**，
不会被当作通过。

## 2. 覆盖清单（需求 → 用例 → 关键断言）

`run_local_regression.py`：

| 要求 | 用例 | 关键断言 |
|---|---|---|
| 同步方法 | `sync.methods` | GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD 服务端实际收到的方法；HEAD 无体但有 Content-Length；模块级入口 |
| 同步请求体 | `sync.payloads` | json 往返 + content-type；form urlencoded；multipart（文件名 + 二进制内容）；裸 bytes（含 NUL）sha256；空 POST 的 `Content-Length: 0`；`params=` 合并 query；自定义头；连发 3 次头不串味 |
| 代理 API 兼容 | `proxy.empty_string` | 故意在环境里塞一个打不通的 `http_proxy`（带 user:password，仅回环），断言会话级与模块级 `proxy=""` 都能绕开它拿到 200 —— 锁住"空串 = 显式禁用"这个保留 API |
| 二进制 / NUL | `binary.nul` | `/binary/4096` 逐字节；0/1 字节边界；1 MiB sha256；chunked 传输解码；stream 与非 stream 一致；上传体 sha256 |
| 重复头 | `headers.duplicate` | `Headers.get_list` 保序返回两条 `X-Dup`；两条 `Set-Cookie`；`r.cookies` 解析出两个；大小写不敏感；请求侧同名头不炸也不重复成多份；重定向各跳头不互相污染 |
| 1xx 中间响应 | `headers.interim` | 服务端先发 `100 Continue` 再发 200，请求体与最终响应都正确 |
| 重定向 | `redirects` | 跟随 3 跳 + history；`allow_redirects=False` 停在 302；循环重定向抛 `TooManyRedirects` 且 `code==47`；302 跳上的 `Set-Cookie` 生效 |
| cookie 隔离 | `cookies.isolation` | 会话 B 看不到 A 的 cookie；同一 cookie 只发一份；同名更新后仍只有一份 |
| 请求级临时 cookie | `cookies.request_scoped` | `cookies=` 与会话罐共存且只发一份、不写进罐；显式 `Cookie` 头本次生效且用完即弃；手工增删清空；`CookieJar` 类型；响应 `Set-Cookie` 解析 |
| gzip | `gzip` | 自动解压（含中文）；gzip 二进制体逐字节；stream 与非 stream 一致 |
| 超时 | `timeout` | `Timeout` 且 `code==28`、消息含 `CURLE_OPERATION_TIMEDOUT`、不带服务端睡完；超时后会话仍可用 |
| 关闭 | `close.session` / `close.response` | 重复 `close()` 幂等；`closed` 翻转；关闭后拒绝新请求（`NbCurlError`）；`with` 退出即关；提前 `close()` 中止流式（不等整份体）；带未读完的流时 `session.close()` 不阻塞；模块级 `stream=True` + `with` |
| 错误之后可继续 | `reuse.after.errors` | 连接被拒 / 短体 / RST / 404+`raise_for_status` / 未知参数 / 非法 URL 六种错误之后，同一会话都能继续正常请求 |
| stream 增量 | `stream.incremental` | 返回时状态码/头可用且没等整份体；首块 < 0.3s；多块产出；总量正确；读完 `is_stream=False`、`stream_consumed=True` |
| iter_content 中途 break 后继续 | `stream.cursor` / `stream.backpressure` | break 后 `content` 补剩余；多次 `next()` 接着读；`content` 之后 `iter_content` 退化为缓存切片；一次读出一大块时 break 也不能丢数据 |
| backpressure + 同步 content 兼容 | `stream.backpressure` | 32 MiB 响应无人读取 1s 时，服务端写出字节 < 90%（有界 + TCP 背压）；随后完整读出 32 MiB；服务端最终写出字节数一致；`content` 剩余语义 |
| 非流式 iter_content | `iter_content.nonstream` | 切片块数与 chunk_size；累计等于 content；可重复整读；`iter_lines` 按 `\n` 切分不丢字节 |
| 资源 | `resources.churn` | 15 轮建/关会话 + 5 轮开流/丢弃后，线程数 ≤ +6、句柄数 ≤ +24（数值记进报告） |
| 异步方法 | `async.methods` | `AsyncSession` 8 并发 gather + 各带参数；异步 POST json / DELETE / HEAD；404 原样；`with` 前后 `closed` |
| 异步错误 | `async.errors` | 异步 `Timeout`（code 28）后可用；`raise_for_status` 抛 `HTTPError` 后可用；`await close()` 幂等；关闭后新请求抛 `NbCurlError` 且不悬挂（超时用协程内的 `asyncio.wait_for` 包，不从 `asyncio.run` 外面套） |
| 异步 stream（同 loop 同步读兼容） | `async.stream.compat` | **在独立进程里**、同一事件循环线程中直接调用同步 `r.content` 与 `r.iter_content()`：aiter_content 中途 break 后 content 补剩余 400；同步 iter_content 严格 5×1000、总字节 5000；先读 1500 再继续读剩余 3500。父进程按 30s 墙钟看门狗杀子进程 —— 真死锁时 asyncio 超时不会触发，只有进程级看门狗收得住（本用例刻意排在 `async.stream` 前） |
| 异步 stream | `async.stream` | 返回即可用状态码/头且不等整份体；`aiter_content` 逐块且首块早；中途 break 后**在同一个协程里直接**同步 `content` 补剩余（不再借 `asyncio.to_thread`），并记录同步读耗时 |
| 取消 | `async.cancel` | 取消传播为 `CancelledError`；被取消的请求还在飞时会话仍能服务别的请求；流式迭代中途取消/关闭；取消后 `close()` 必须在 4s 预算内返回（12s 慢请求） |
| 关闭与在飞请求 | `async.close_inflight` | 有在飞请求时 `close()` 不悬挂；已接纳的在飞/排队请求被正常排空（`success`）；关闭后新请求抛 `NbCurlError`；并发重复 `close()` 幂等 |
| 服务端生命周期 | `server.lifecycle` / `server.cleanup` | 动态端口；admin 计数属于本进程；套件结束时端口已释放（连接被拒） |

另外四个套件：

| 套件 | 覆盖 | 关键口径 |
|---|---|---|
| `test_protocols.py` | 本地 CA 的 TLS 校验、无亲缘错误 CA 被拒、SAN 不匹配被拒、真实 H2 协商（ALPN 全 `h2`）、WebSocket 明文/TLS 收发（含分片与控制帧） | 证书现场生成，走客户端 `verify=True` + `ca_path=`；H3 只登记**未覆盖**，不假装测过 |
| `test_http3.py` | 本地 aioquic H3：单请求、连接复用、8 并发、错误 CA、HTTP3_ONLY 常量 | 断言 `resp.http_version == "3"` 且服务端 ALPN 全 `h3`，**不许静默降级**；响应体含 NUL 逐字节比对 |
| `test_async_protocols.py` | 同一个 `AsyncSession(max_clients=8)` 上的 H2 / H3 multi 并发、顺序复用、流式、错误 CA | 并发连接数如实记录；顺序 2 请求只新增 1 条连接（复用硬断言） |
| `test_stream_metadata.py` | 流式读完后 cookie 入罐与后续发送、头就绪 vs 完成后的元信息、HEAD/204/1xx、重定向后的 `url`/`history` | 只对照本仓库实现的实际行为，不从其它库搬语义 |
| `test_parity_edges.py` | basic auth 不残留、请求级 timeout 覆盖与复位、`resolve=`、`curl_options`、latin-1/utf-8 编码、deflate、短体报错 | 短体必须报 `CURLE_PARTIAL_FILE`（code 18），不许静默成功 |

## 3. 结果怎么读

* 每条断言一行 `[PASS]`/`[FAIL]`，`[FAIL]` 带实测值；`[info]` 是记录下来的事实（不是跳过）。
* 末尾打印断言总数、失败清单（含用例名）、最慢 5 个用例；`--json` 里有每条断言的明细。
* `async.cancel` 用 12s 慢请求验证"取消 + `close()` 4s 预算"，实测整套跑完 **0.61s**
  —— 说明取消是真的把请求中止了，不是"调用方不等了、后台还在跑"（后者会顶到 12s）。
* `async.close_inflight` 实测 `close()` 约 3.5s 返回，在飞与排队请求都正常完成（`success 200`），
  关闭后的新请求抛 `NbCurlError`，重复 `close()` 幂等。
* `async.stream.compat` 记录子进程总耗时。
* 代理环境变量只出现在报告的变量名里（`proxy_env_scrubbed`），不含值。
* 运行前后各记一次实现目录的 `.py` 哈希，两边不一致会在末尾警告"本次结果不作为结论依据"。

## 4. 本套件在本仓库实现上的实跑结果

环境：Windows + CPython 3.11.9 + 本仓库 `nb_curl`，两个 FFI 后端各跑一遍
（`cffi` 与 `ctypes`）。命令见 §1，结果如下（**全部 0 失败**）：

| 套件 | cffi | ctypes |
|---|---|---|
| `run_local_regression.py` | 240 条断言，通过 240 | 240 条断言，通过 240 |
| `test_protocols.py` | 69 条断言，通过 69（另有 1 项 `[NOT-COVERED]`：H3 见 §5） | 69 条断言，通过 69 |
| `test_http3.py` | 29 条断言，通过 29，blocked 0 | 29 条断言，通过 29，blocked 0 |
| `test_async_protocols.py` | 37 条断言，通过 37，blocked 0 | 37 条断言，通过 37，blocked 0 |
| `test_stream_metadata.py` | 54 条，通过 54 | 54 条，通过 54 |
| `test_parity_edges.py` | 33 条断言，通过 33 | 33 条断言，通过 33 |
| `test_socket_changes.py` | 退出码 0 | 退出码 0 |

两点如实说明：

1. **`test_stream_metadata.py` 有一条与调度有关的偶发**：`[cookie] 头就绪时 url 仍是请求 URL`
   这个断言锁的是"重定向后的最终 URL 何时刷新"的时序。本机 cffi 后端 14 次实跑里出现过
   1 次先看到最终 URL（`.../cookies` 而不是请求的 `.../cookies/set?...`），
   同一台机器上 4 次连跑里也有过 1 次；ctypes 后端连跑未复现。
   断言本身没有放宽（比较值与阈值未动），如需彻底消除要改被测实现的刷新时机。
2. `run_local_regression.py` 的 `resources.churn` 记的是**相对增量**（线程 ≤ +6、句柄 ≤ +24），
   具体数值随机器与后端浮动，判定用的是上界而不是等值。

## 5. 尚未覆盖（不要当成测过了）

* **H3 服务端**：`test_protocols.py` 不含 H3（那个套件只做 TLS/H2/WS）；H3 由
  `test_http3.py` 与 `test_async_protocols.py` 用 aioquic 覆盖。前者在报告里把 H3 记成
  `[NOT-COVERED]` 是**如实登记**，不是失败。
* **指纹 / 反检测**：ja3/ja4、akamai、`diy_fp`、内置预设这些需要真实 TLS 与线上服务，
  本目录按"只打 127.0.0.1、不碰第三方站点"的约束**故意不做**；
  后端的 `backend_name()/backend_info()` 只记录不比较。
* **代理、DNS 覆盖（`resolve=` 之外的场景）、`tcp=` 画像的线上效果**：本地只验证了
  "空串禁用代理""本地别名能被 resolve"这类开关，不等于代理/DNS/TCP 功能已覆盖。
* **`pool_keys()` 连接池分区隔离、复用自愈、`max_clients` 排队与"排队中取消"**：
  需要专门的占满连接场景；当前只覆盖了"取消一个在飞的慢请求"和"取消流式迭代"。
* **DNS / 连接建立阶段的取消与超时**：慢请求覆盖的是"已连上、服务端不回"的阶段。
* **重试与非幂等请求不重放**：没有本地故障注入点（需要"复用失败一次再成功"的可控服务端）。
* **`stream=True` 与 `tcp=` 同用时的告警语义**：属于告警口径，未在本目录断言。
* **长跑 FD/RSS 泄漏**：套件里只有 churn 的轻量检查；长跑与 RSS 趋势要单独做 soak 用例。
* **开环/固定 QPS、CPU 亲和性**：不属于功能回归。

## 6. 已确认口径（不再是疑点）

1. **请求侧同名头**：按当前实现既有语义（同名去重，最终只发一条），**不扩充**行为。
   套件只断言"不炸、不出现多余的第 3 条"，两种语义都放行；
   将来若要支持真正的重复请求头，再改断言。
2. **游标语义**：必须**总字节守恒**（读过的 + 后续读到的 = 整份体，不丢不重），
   且 `iter_content` **严格按 `chunk_size` 切片**（到达块更大也要切开）。
   `stream.cursor` / `stream.backpressure` / `async.stream.compat` 就是按这个口径判的。
3. **关闭后的异常类型**：统一 `NbCurlError`（同步、异步、以及 close 时还在飞的请求）。
   同步与"关闭后新请求"两处已经是硬断言；在飞请求的归宿由 `async.close_inflight` 记录
   （实测：正常排空完成）。
4. **取消预算**：保留"12s 慢请求 + `close()` 预算 4s"这个口径（它用来区分
   "真中止"与"等它跑完"），不改数值。
5. **`proxy=""`**：保留"空串 = 显式禁用代理"的公开 API（`proxy.empty_string` 兜住）。
