# c_src —— C 内核源码（补丁 / 桥接层 / 构建脚本）

nb-curl 的 wheel 里**已经包含编译好的 C 内核**，普通使用者不需要这个目录。
这里放的是「想把 C 内核从源码重新编出来」所需的全部材料，供有需要的人自行构建。

## 目录

| 路径 | 是什么 |
| --- | --- |
| `patches/` | 打在上游依赖上的补丁。`curl.patch` 来自 [curl-impersonate](https://github.com/lwthiker/curl-impersonate)；BoringSSL / nghttp3 / ngtcp2 / brotli / OpenBSD 这几个是为本项目的构建需要一并收进来的；`nb_curl.patch` 是本项目相对「上游 + curl-impersonate」的增量，改动处标注 `Curl_cffi rework`，可直接 grep |
| `native/` | C 桥接层源码 `nb_curl_bridge.c` / `nb_curl_bridge.h`。它把 libcurl-impersonate 的 C API 收敛成一组扁平接口，供 Python 侧直接调用 |
| `build/` | 构建脚本。`windows/`、`linux/` 对应两个平台；`prepare_sources.sh` 按版本锚点把上游源码拉下来并打好补丁；`_cffi_build.py` 把桥接层编成 Python 扩展 |

## 大致流程

```bash
# 1) 取上游源码（curl / BoringSSL / nghttp3 / ngtcp2）并按锚点打补丁
bash build/prepare_sources.sh

# 2) 编 BoringSSL + curl + HTTP/3 + 桥接层
bash build/windows/build_all.sh        # 或 build/linux/build_all.sh

# 3) 编出 nb_curl 的 CFFI 扩展
bash build/windows/build_cffi.sh
```

依赖的具体版本锚点写在 `build/prepare_sources.sh` 头部。Windows 上 MSVC / Windows SDK / cmake / ninja
等工具路径由 `build/windows/toolchain.sh` 自动探测，也可用 `NB_CURL_*` 环境变量覆盖。

## 注意

这些脚本原本工作在**完整源码树**的根目录 —— 即根下同时有 `deps/`、`build/`、`python/` 三个目录时可以直接跑。
放进本仓库的 `c_src/` 之后，脚本内部的相对路径（`REPO="$(cd ../.. && pwd -W)"`、`PROJECT="$REPO/python"`）
需要按实际布局调整，或者把 `c_src/` 里的内容摊回一个完整源码树再执行。
