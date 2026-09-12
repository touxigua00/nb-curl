# 更新日志

nb-curl 的版本变更记录。版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

> **发布状态**：`0.2.0` 是首个 PyPI 版本，`0.2.2` 起同时提供 Windows x64 与 Linux x86_64 轮子。
> 更早的 `0.1.x` 当时叫 `curlx`，未对外发布，仅作历史记录保留。

## [0.2.1] - 2026-09-12

### 修复

- 并发场景下关闭 `Session` / `AsyncSession` 可能崩溃：连接池在关闭时会把仍在使用的句柄一并释放。
- `AsyncSession.close()` 改为异步方法，现在需要 `await session.close()`（或直接用 `async with`）。

## [0.2.0] - 2026-09-11

### 变更

- 项目改名：发行名 `nb-curl`、导入名 `nb_curl`（原名 `curlx`）。
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
