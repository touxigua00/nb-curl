# Linux 构建 —— 在 Linux 上构建 nb-curl

这个目录包含了**在 Linux 上从零构建 nb-curl 所需的全部东西**：逐步构建脚本、
CFFI 扩展构建、wheel 打包、测试、Docker 与一键部署脚本。

（源码包不在这个目录，在 **`deps/sources/`** —— 与 Windows 构建共用。
 项目本体在 **`python/`**。本套件只负责"把源码编成 Linux 可用的产物"。）

已验证环境：**Ubuntu 24.04.4 LTS / x86_64 / gcc 13.3 / Python 3.12.3**，
构建后 **81 项功能测试全部通过**，且 ja4/akamai 指纹与 Windows 版**逐字节一致**。

---

## 0. 一条命令

所有命令都在**仓库根**（`<仓库根>`）执行：

```bash
bash build/linux/scripts/build_all.sh
```

之后：

```bash
bash build/linux/scripts/90_test.sh                          # 跑测试
pip install python/dist/nb_curl-0.3.1-py3-none-linux_x86_64.whl # 安装
```

耗时参考（2 核 / 4GB 虚拟机）：**约 10–15 分钟**，其中 BoringSSL 编译占大头。

---

## 1. 它产出什么

| 产物 | 路径 | 说明 |
| --- | --- | --- |
| native 桥接层 | `python/nb_curl/_lib/libnb_curl_native.so` | 静态链接 libcurl-impersonate + BoringSSL，28MB |
| CFFI 扩展 | `python/nb_curl/_nb_curl_cffi.cpython-3XX-x86_64-linux-gnu.so` | CFFI API 模式，可选 |
| wheel | `python/dist/nb_curl-0.3.1-py3-none-linux_x86_64.whl` | 可直接 pip install |

---

## 1.5 分发策略：wheel 里只放二进制

`50_wheel.sh` 打完包会自动调用 `tools/check_binary_only.py` 校验：
**wheel 里只允许有编译产物，出现任何 C 源码就直接失败退出。**

实际 wheel 内容（已校验）：

```
nb_curl/__init__.py  *_backend_*.py  *_native.py  ...   纯 Python
nb_curl/_lib/libnb_curl_native.so                         ← 编译产物（28MB）
nb_curl/_nb_curl_cffi.cpython-312-x86_64-linux-gnu.so     ← 编译产物
nb_curl/_lib/cacert.pem
```

**没有** `native/nb_curl_bridge.c`、`.h`、`.a`、`.o`，
也没有构建期专用模块 `_cffi_build.py`（内含 ABI cdef 声明）。

所以：

* 别人拿到 wheel 后 `pip install` 即可使用，**不需要编译器、不需要你的源码**；
* 你的构建工程（`deps/sources/`、`build/linux/`、`python/native/`）留在自己机器上即可。

两条纪律：

1. **只发 wheel**，不要把 `python/` 源码目录或 sdist 发出去；
2. 要发给别人时，只给 `python/dist/*.whl` 这一个文件。

> wheel 里只有机器码，但**机器码仍可被逆向**，字符串常量在 `.so` 里可见。
> 这是所有二进制分发的共同边界。想再抬高门槛可对 `.so` 做 `strip`
> （本套件已用 `-g0` 编译）。

---

## 2. 依赖

`build/linux/scripts/00_deps.sh` 会用 apt 装好下面这些（需要 sudo）：

```bash
build-essential cmake ninja-build pkg-config perl nasm \
zlib1g-dev libbrotli-dev libzstd-dev libnghttp2-dev libidn2-dev \
python3-dev python3-venv python3-pip ca-certificates file
```

其中 **perl 是 BoringSSL 的 perlasm 需要的**（生成汇编），别漏。

---

## 3. 逐步构建

| 脚本 | 干什么 | 耗时 |
| --- | --- | --- |
| `build/linux/scripts/00_deps.sh` | apt 装依赖 | 1–2 min |
| `build/linux/scripts/10_boringssl.sh` | 编译 BoringSSL（`libssl.a` / `libcrypto.a`） | 8–12 min |
| `build/linux/scripts/15_quic.sh` | 编译 ngtcp2（BoringSSL 后端）+ nghttp3 → HTTP/3 的传输层与帧层 | 3–5 min |
| `build/linux/scripts/20_curl.sh` | 编译 libcurl-impersonate（`libcurl-impersonate.a`，带 ECH + HTTP/3） | 1–2 min |
| `build/linux/scripts/30_bridge.sh` | 编译 `libnb_curl_native.so` | <10 s |
| `build/linux/scripts/40_cffi.sh` | 编译 CFFI API 模式扩展（可选） | <1 min |
| `build/linux/scripts/50_wheel.sh` | 打 wheel 并本机验证 | <1 min |

单个脚本可以单独重跑，中间产物都在 `_work/` 下，已存在会自动跳过
（`NB_CURL_FORCE_REBUILD=1` 可强制重编 curl / ngtcp2）。

```bash
bash build/linux/scripts/build_all.sh --no-deps     # 依赖已装好，跳过 apt
NB_CURL_JOBS=8 bash build/linux/scripts/build_all.sh  # 指定并行度
```

---

## 4. 源码包（在 `deps/sources/`）

两个**已经打好 curl-impersonate 补丁**的源码包，Windows 与 Linux 构建共用：

| 文件 | 内容 |
| --- | --- |
| `boringssl-patched.tar.gz` (75MB) | BoringSSL@156c7b75，`ssl.h` 里含 extension order / GREASE / ALPS / ECH 等钩子 |
| `curl-8.22.0-patched.tar.gz` (3.9MB) | curl 8.22.0，含 `lib/impersonate.c`（40 套内置浏览器指纹）与 `CURLOPT_IMPERSONATE` 等新选项 |

**不要换成上游原始源码**，否则 `CURLOPT_TLS_EXTENSION_ORDER` 之类会编译失败。
脚本里有 `grep` 校验，用错包会直接报错退出。

如果你更想自己从上游拉：

```bash
git clone https://boringssl.googlesource.com/boringssl
git -C boringssl checkout 156c7b75ae9b8c3b3f847acf264f17594c3859fb
patch -p1 -d boringssl < ref_curl_impersonate/patches/boringssl.patch
curl -L -o curl-8.22.0.tar.gz https://curl.se/download/curl-8.22.0.tar.gz
tar xzf curl-8.22.0.tar.gz
patch -p1 -d curl-8.22.0 < curl_impersonate_curl.patch
```

---

## 5. Linux 上踩到的坑（都已在脚本里修好）

这些在 Windows 上都不会出现，因为 cl.exe 会自动带上 C++ 运行时。记录在这里，
方便你以后换发行版或升级 BoringSSL 时对照。

### 5.1 BoringSSL 的 Linux 库里有 C++ 代码 → 必须补 `-lstdc++`

BoringSSL 在 Linux 上会编译 `ssl/encrypted_client_hello.cc`、`ssl/extensions.cc`
等 C++ 源文件，静态库里因此带 C++ 运行时符号。链接时报：

```
undefined reference to `__gxx_personality_v0'
undefined reference to `__cxa_allocate_exception'
undefined reference to `__cxa_throw'
```

所以 `build/linux/scripts/30_bridge.sh` 的链接行末尾有 `-lstdc++`。

### 5.2 curl 的符号检测被误判 → 报 "ECH support missing"

curl 用 `check_function_exists` 探测 `SSL_set0_wbio` / `SSL_set1_ech_config_list`，
生成的探测程序**没链 libstdc++**，链接失败 → 被判定成"符号不存在" → 报：

```
CMake Error at CMakeLists.txt:1113 (message):
  ECH support missing in AWS-LC/BoringSSL/OpenSSL/Rustls/wolfSSL
```

**但这两个符号其实都在 `libssl.a` 里**（`nm -g --defined-only libssl.a` 能看到
`T SSL_set1_ech_config_list`）。而且 Ubuntu 默认 `-Wl,--as-needed`，把 `-lstdc++`
放在 OpenSSL 库之前会被丢掉，所以光加 `CMAKE_REQUIRED_LIBRARIES` 不一定管用。

`build/linux/scripts/20_curl.sh` 的做法是**直接把检测结果写进 CMake 缓存**：

```bash
-DHAVE_SSL_SET1_ECH_CONFIG_LIST=1 -DHAVE_SSL_SET0_WBIO=1
```

CMake 的 `check_function_exists` 见到同名变量已定义就跳过检测。

> 为什么非得开 ECH：`lib/impersonate.c` 里大量浏览器预设带 `.ech = "true"`，
> 关掉 `USE_ECH` 会破坏指纹保真度。

### 5.3 静态库叫 `libcurl-impersonate.a`，不叫 `libcurl.a`

curl-impersonate 的补丁把库名改了。脚本里两种名字都兼容。

### 5.4 桥接层源码原来硬编码了 `#include <windows.h>`

已改成 `#ifdef _WIN32` 条件包含（顺带确认了 `windows.h` 其实根本用不到）。
**Windows 和 Linux 现在编译的是同一份 `nb_curl_bridge.c`。**

### 5.5 重编 CFFI 扩展时必须设 `NB_CURL_BACKEND=ctypes`

这是个很隐蔽的坑，症状是"重编永远失败"，而且看起来像杀毒软件在锁文件：

```
PermissionError: [Errno 13] Permission denied: '.../_nb_curl_cffi.cpython-312-x86_64-linux-gnu.so'
/warn/ 无法删除过期产物 ... [WinError 5] 拒绝访问
```

原因：`python -m nb_curl._cffi_build` 会**先执行 `nb_curl/__init__.py`**，
进而加载 `_native` 与 cffi 后端，把**已存在的** `_nb_curl_cffi*.so` 映射进当前进程；
随后同一进程再去删除/覆盖这个文件，必然失败。

`40_cffi.sh` 里的对策：

```bash
NB_CURL_BACKEND=ctypes "$VENV/bin/python" -m nb_curl._cffi_build --quiet
```

强制 ctypes 后端就不会去 import `_nb_curl_cffi`，文件自然不锁。

> 附带一条：构建脚本里**不要用 `env -u VAR=... cmd` 这种包装**调用 Python
> —— 在带沙箱钩子的环境里偶发"静默不执行、退出码却是 0"。
> 正确做法是在脚本顶部 `unset VAR`，然后直接调用。

### 5.6 glibc 兼容性（发布给别人时要注意）
在 Ubuntu 24.04（glibc 2.39）上编出来的 `.so`，拿到 Ubuntu 22.04（glibc 2.35）
或更老的系统会报：

```
GLIBC_2.39 not found
```

**自用无所谓；要分发给别人，请在目标最低版本的系统里构建**，或者用容器：

```bash
cd <仓库根>                                  # Dockerfile 里的 COPY 用的是仓库根
docker build -f build/linux/Dockerfile -t nb_curl-linux-builder .
docker run --rm -v "$PWD/python/dist:/out" nb_curl-linux-builder
```

`Dockerfile` 用的是 `ubuntu:22.04`（glibc 2.35），产出的 wheel 在
Ubuntu 22.04+ / Debian 12+ / RHEL 9+ 都能用。

---

## 6. 安装与使用

### 方式 A：装 wheel（推荐）

```bash
pip install python/dist/nb_curl-0.3.1-py3-none-linux_x86_64.whl
```

### 方式 B：直接从源码目录装

```bash
pip install ./python
```

### 方式 C：不安装，直接加路径

```bash
export PYTHONPATH=$PWD/python:$PYTHONPATH
python -c "import nb_curl; print(nb_curl.native_version())"
```

装好后：

```python
import nb_curl

r = nb_curl.get("https://www.xcctls.top/all", impersonate="chrome116")
print(r.status_code, r.http_version)     # 200 2
print(r.json()["client_hello"]["ja4"]["ja4"])

with nb_curl.Session(impersonate="chrome150") as s:
    s.get("https://example.com")
```

---

## 7. 运行期依赖

`libnb_curl_native.so` 在运行期依赖这些**系统库**（Ubuntu 默认就有，发行版基本都带）：

```
libnghttp2  libbrotlidec  libbrotlicommon  libzstd  libz
libidn2     libstdc++     libgcc_s         libc
```

用 `ldd python/nb_curl/_lib/libnb_curl_native.so` 可以核对。若目标机器极简，
补装 `libnghttp2-14 libbrotli1 libzstd1 zlib1g libidn2-0` 即可。

---

## 8. 目录结构

```
<仓库根 = <仓库根>>
├── python/                        ★ 项目本体（Windows/Linux 共用同一份）
│   ├── native/nb_curl_bridge.{c,h}    桥接层源码（跨平台）
│   ├── nb_curl/                       Python 包（含 _lib/ 动态库、dist 在上一层）
│   ├── tests/test_nb_curl.py          81 项功能测试
│   └── dist/                        wheel 产物（Windows 与 Linux 都放这）
├── deps/sources/                  ★ 源码包（两个平台共用，别删）
│   ├── boringssl-patched.tar.gz
│   └── curl-8.22.0-patched.tar.gz
└── build/linux/                   ← 本目录
    ├── README.md                  你正在看的
    ├── Dockerfile                 容器里构建（解决 glibc 兼容）
    ├── deploy_to_vm.sh            从 Windows 一键部署到虚拟机并构建
    ├── scripts/
    │   ├── lib.sh                 公共变量（ROOT 由 ../../.. 推出来）
    │   ├── 00_deps.sh             apt 依赖
    │   ├── 10_boringssl.sh        BoringSSL
    │   ├── 15_quic.sh             ngtcp2 + nghttp3（HTTP/3）
    │   ├── 20_curl.sh             libcurl-impersonate（含 ECH 检测绕过的说明）
    │   ├── 30_bridge.sh           libnb_curl_native.so
    │   ├── 40_cffi.sh             CFFI API 模式扩展
    │   ├── 50_wheel.sh            wheel 打包 + 校验
    │   ├── 90_test.sh             测试
    │   └── build_all.sh           一键全流程
    └── _work/                     构建中间目录（可删）
        ├── boringssl/  curl-8.22.0/  prefix/  venv/
```

---

## 9. 常见问题

**Q：能不能不编 BoringSSL？**
A：不行。nb-curl 的指纹能力依赖 curl-impersonate 给 BoringSSL 打的钩子
（extension order / GREASE / ALPS / ECH）。系统自带的 OpenSSL 没有这些。

**Q：`40_cffi.sh` 失败，能用吗？**
A：能。CFFI 只是可选加速（实测比 ctypes 快约 1.2x，对端到端时延影响 <0.1%）。
失败时 `import nb_curl` 会自动回退到 ctypes 后端。
自检：`nb_curl.backend_info()` 里的 `cffi_fallback_reason` 会告诉你原因。

**Q：能交叉编译到 ARM 吗？**
A：可以，但要改 `build/linux/scripts/10_boringssl.sh` / `20_curl.sh` 走交叉工具链，并处理
`CMAKE_SYSTEM_NAME` 与 sysroot。目前脚本只验证了 x86_64。

**Q：`_work/` 能删吗？**
A：能，删了下次会重新解包和编译。`deps/sources/` 别删（除非你能自己拉源码）。

**Q：换 Python 版本要重编吗？**
A：**ctypes 后端不用**（纯 Python），只有 `_nb_curl_cffi*.so` 需要按 Python 版本重编。
重编很快：`bash build/linux/scripts/40_cffi.sh && bash build/linux/scripts/50_wheel.sh`。
