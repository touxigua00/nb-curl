# 在容器里构建 Linux wheel（解决 glibc 兼容性）
#
# 为什么需要它：
#   直接在 Ubuntu 24.04 上构建的 .so 会链接 glibc 2.39，拿到
#   Ubuntu 22.04（2.35）或更老的容器里会报 "GLIBC_2.3x not found"。
#   要给别人用，就在**目标最低版本**的系统里构建。
#
# 用法（在仓库根 <仓库根> 下执行；build context 是仓库根）：
#   docker build -f build/linux/Dockerfile -t nb-curl-linux-builder .
#   docker run --rm -v "$PWD/python/dist:/out" nb-curl-linux-builder
#   # 产物：python/dist/nb_curl-<版本>-py3-none-linux_x86_64.whl
#
# 说明：
#   * 只 COPY Linux 构建需要的东西（源码包 + 脚本 + 项目本体），
#     不传 deps/windows-prebuilt（MSVC 产物）和 deps/tools（Windows 工具）。
#   * 基础镜像用 ubuntu:22.04 → 产出的 wheel 在 Ubuntu 22.04+ / Debian 12+ / RHEL 9+ 可用。
#     想要更广兼容性，换成对应的 manylinux 镜像（注意 Python 在 /opt/python 下）。
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV NB_CURL_JOBS=4

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build pkg-config perl nasm \
      zlib1g-dev libbrotli-dev libzstd-dev libnghttp2-dev libidn2-dev \
      python3-dev python3-venv python3-pip \
      ca-certificates file \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /repo

# 整个仓库上下文（.dockerignore 已排除 .venv / _work / dist 等）
#
# 前置：宿主机先跑 `bash deps/prepare_sources.sh` 生成 deps/sources/，
#       否则容器里没有可编译的源码。
COPY . /repo/

# 依赖已在镜像里装好 → --no-deps；产出 wheel 到 python/dist/
RUN bash build/linux/scripts/build_all.sh --no-deps

RUN mkdir -p /out && cp -v /repo/python/dist/*.whl /out/ 2>/dev/null || true

CMD ["bash", "-lc", "ls -la /out/"]
