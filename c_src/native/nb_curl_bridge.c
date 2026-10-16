/*
 * nb_curl_bridge.c — nb_curl 的稳定 C ABI 桥接层实现
 *
 * 链接：静态 libcurl-impersonate + BoringSSL(ssl/crypto) + nghttp2/zlib/brotli/zstd
 * 编译时必须定义 CURL_STATICLIB（否则 curl.h 按 dllimport 声明，链接失败）。
 *
 * 跨平台：本文件在 Windows 与 Linux 上编译同一份源码。
 *   Windows: build_native.sh    -> nb_curl_native.dll
 *   Linux  : scripts/30_bridge.sh -> libnb_curl_native.so（需 -lstdc++）
 */
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  define NOMINMAX
#  include <windows.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "nb_curl_bridge.h"
#include <curl/curl.h>
#include <curl/websockets.h>

#ifdef _WIN32
#  define nb_strdup _strdup
#else
#  define nb_strdup strdup
#endif

/* TCP 层画像用到的 socket 头。
   Windows：setsockopt / WSAIoctl / IPPROTO_IP / SO_RCVBUF 由 curl.h 引入的
   winsock2.h 提供，不需要额外 include。 */
#ifndef _WIN32
#  include <errno.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#endif

/* 按**显式长度**复制（二进制安全）。
   不能用 nb_strdup：它内部是 strlen，遇到响应体里的 \0 就会提前截断，
   而我们要把真实长度一并返回给 Python，结果就是 Python 读到越界内存。 */
static char* nb_strndup(const char* p, size_t n)
{
    char* out;
    if(!p)
        return NULL;
    out = (char*)malloc(n + 1);
    if(!out)
        return NULL;
    if(n)
        memcpy(out, p, n);
    out[n] = '\0';
    return out;
}

/* ================================================================== */
/* 可变长缓冲区                                                        */
/* ================================================================== */
typedef struct {
    char*  data;
    size_t len;
    size_t cap;
} nb_buf;

static int nb_buf_reserve(nb_buf* b, size_t need)
{
    size_t ncap;
    char*  np;
    if(b->cap - b->len > need)
        return 1;
    ncap = b->cap ? b->cap : 512;
    while(ncap - b->len <= need)
        ncap *= 2;
    np = (char*)realloc(b->data, ncap);
    if(!np)
        return 0;
    b->data = np;
    b->cap = ncap;
    return 1;
}

static int nb_buf_append(nb_buf* b, const char* p, size_t n)
{
    if(!nb_buf_reserve(b, n + 1))
        return 0;
    memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = '\0';
    return 1;
}

static void nb_buf_reset(nb_buf* b)
{
    b->len = 0;
    if(b->data)
        b->data[0] = '\0';
}

static void nb_buf_free(nb_buf* b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

/* 空闲句柄不能无限保留历史超大正文容量：容量超过 keep 就整块释放，
   下次 append 按需重新增长（否则一个 100MB 响应会让这只句柄永久占着 100MB）。 */
#define NB_BUF_KEEP_CAP (16u * 1024u)

static void nb_buf_shrink(nb_buf* b)
{
    if(b->cap > NB_BUF_KEEP_CAP)
        nb_buf_free(b);
    else
        nb_buf_reset(b);
}

/* 结果所有权移交：把 C 累积缓冲整块交给调用方（不做任何复制），
   句柄内缓冲置空。调用方负责 free（easy_free_string）。 */
static void nb_buf_take(nb_buf* b, char** out, size_t* len)
{
    if(len) *len = b->len;
    if(out) *out = b->data;
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

/* ================================================================== */
/* 句柄关联数据（与 handle 同生命周期）                                 */
/* ================================================================== */
typedef struct {
    int option;
    struct curl_slist* list;
} NbOptSlistEntry;

typedef struct {
    struct curl_slist* headers;     /* 用户头，保序 */
    void*  owner;                   /* 所属 CURL*（快照时要回查 ACTIVESOCKET） */
    struct curl_slist* resolve;     /* DNS 覆盖条目，CURLOPT_RESOLVE 只存指针 */
    char*  post_body;               /* POST 体副本，避免跨语言生命周期问题 */
    size_t post_len;
    char*  method;                  /* 请求方法副本（在 perform 前统一应用） */
    nb_buf body;                    /* 响应体累积缓冲（C 层，不进 Python 回调） */
    nb_buf head;                    /* 响应头累积缓冲 */
    /* curl_options 直传的 slist 类 option 的内存托管。
       每个出现过的 option 占一个槽位；重复设置同一 option 会先释放旧 list 再放新。 */
    NbOptSlistEntry* opt_slists;
    int    n_opt_slists;

    /* --- TCP 层画像（JA4T）。-1 = 该项不设置 ---------- */
    int    tcp_enabled;         /* 是否注册了 sockopt 回调 */
    int    tcp_sockopt_ran;     /* 本次 perform 是否真的建了新连接 */
    int    tcp_ttl;
    int    tcp_mss;
    int    tcp_window;          /* 仅供回读比对，不下发 */
    int    tcp_wscale;          /* 仅供回读比对，不下发 */
    int    tcp_rcvbuf;          /* SO_RCVBUF：window / wscale 的实际落点 */
    int    tcp_timestamp;
    int    snap_ok;             /* 传输期间是否成功抓到快照 */
    int    snap_ttl;
    int    snap_mss;
    int    snap_wscale;
    int    snap_window;
    int    snap_rcvbuf;
    int    snap_timestamp;
    char   tcp_err[256];        /* socket 层设置失败的原因 */
    int    tcp_err_set;
} HandleData;

/* 结构体字段默认值：-1 = 不设置。calloc 给的是 0，必须显式复位。 */
static void nb_tcp_state_reset(HandleData* hd)
{
    hd->tcp_enabled = 0;
    hd->tcp_sockopt_ran = 0;
    hd->tcp_ttl = -1;
    hd->tcp_mss = -1;
    hd->tcp_window = -1;
    hd->tcp_wscale = -1;
    hd->tcp_rcvbuf = -1;
    hd->tcp_timestamp = -1;
    hd->snap_ok = 0;
    hd->snap_ttl = -1;
    hd->snap_mss = -1;
    hd->snap_wscale = -1;
    hd->snap_window = -1;
    hd->snap_rcvbuf = -1;
    hd->snap_timestamp = -1;
    hd->tcp_err[0] = '\0';
    hd->tcp_err_set = 0;
}

static void nb_free_opt_slists(HandleData* hd)
{
    int i;
    if(!hd || !hd->opt_slists)
        return;
    for(i = 0; i < hd->n_opt_slists; i++)
        curl_slist_free_all(hd->opt_slists[i].list);
    free(hd->opt_slists);
    hd->opt_slists = NULL;
    hd->n_opt_slists = 0;
}

static HandleData* nb_hd(nb_easy* e)
{
    HandleData* hd = NULL;
    if(!e)
        return NULL;
    if(curl_easy_getinfo((CURL*)e, CURLINFO_PRIVATE, &hd) != CURLE_OK)
        return NULL;
    return hd;
}

static void nb_hd_release(HandleData* hd)
{
    if(!hd)
        return;
    if(hd->headers)
        curl_slist_free_all(hd->headers);
    if(hd->resolve)
        curl_slist_free_all(hd->resolve);
    free(hd->post_body);
    free(hd->method);
    nb_buf_free(&hd->body);
    nb_buf_free(&hd->head);
    nb_free_opt_slists(hd);
    free(hd);
}

/* ================================================================== */
/* TCP 层画像（JA4T）                                                 */
/* ================================================================== */
/* 观测点与平台能力（细节见 docs/12-TCP指纹修改设计与验证.md 与技能 nb-curl-tcp-ja4t）：
     TTL          跨平台（IP_TTL）
     SO_RCVBUF    window 与 wscale 共用的落点，跨平台
     TCP_MAXSEG   只有 Linux 有；Windows 任何 optname 都是 WSAENOPROTOOPT，
                  MSS 只能改网卡 MTU（netsh，Python 侧提供辅助函数）
     TCP 时间戳    Windows 逐 socket（optname 10）；Linux 只有全局 sysctl
   回读：Linux getsockopt(TCP_INFO / SO_RCVBUF / TCP_MAXSEG)；
         Windows WSAIoctl(SIO_TCP_INFO)。
   **必须在传输期间抓快照**：perform 之后套接字常已被对端关掉，那时
   getsockopt 一律失败，校验会静默变成"从未执行"。 */

#ifdef _WIN32
#  define NB_TCP_TIMESTAMPS_OPTNAME 10        /* TCP_TIMESTAMPS，SDK 没有这个宏 */
#  define NB_SIO_TCP_INFO            0xD8000027
#  define NB_SO_OPTVAL(p)     ((const char*)(p))
#  define NB_SO_OPTVAL_RW(p)  ((char*)(p))          /* getsockopt 的 optval 非 const */
#  define NB_SO_OPTLEN(p)     ((int)sizeof(*(p)))
#else
#  define NB_SO_OPTVAL(p)     ((const void*)(p))
#  define NB_SO_OPTVAL_RW(p)  ((void*)(p))
#  define NB_SO_OPTLEN(p)     ((socklen_t)sizeof(*(p)))
#endif

static void nb_tcp_note(HandleData* hd, const char* what)
{
    if(!hd || hd->tcp_err_set)
        return;
    hd->tcp_err_set = 1;
#ifdef _WIN32
    snprintf(hd->tcp_err, sizeof(hd->tcp_err),
             "%s setsockopt 失败（Windows 错误码 %d）", what,
             (int)WSAGetLastError());
#else
    snprintf(hd->tcp_err, sizeof(hd->tcp_err),
             "%s setsockopt 失败（errno %d）", what, errno);
#endif
}

/* CURLOPT_SOCKOPTFUNCTION：连接建立**之前**按 socket 设值。
   没设的项（-1）一律不碰，因此本机默认窗口 / wscale 保持原样。 */
static int nb_sockopt_cb(void* clientp, curl_socket_t fd, curlsocktype purpose)
{
    HandleData* hd = (HandleData*)clientp;
    int v;

    (void)purpose;
    if(!hd || fd == CURL_SOCKET_BAD)
        return CURL_SOCKOPT_ERROR;

    hd->tcp_sockopt_ran = 1;

    if(hd->tcp_ttl > 0) {
        v = hd->tcp_ttl;
        if(setsockopt(fd, IPPROTO_IP, IP_TTL, NB_SO_OPTVAL(&v), NB_SO_OPTLEN(&v)) != 0)
            nb_tcp_note(hd, "TTL(IP_TTL)");
    }
    if(hd->tcp_rcvbuf > 0) {
        v = hd->tcp_rcvbuf;
        if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, NB_SO_OPTVAL(&v), NB_SO_OPTLEN(&v)) != 0)
            nb_tcp_note(hd, "SO_RCVBUF");
    }
    if(hd->tcp_mss > 0) {
#ifdef _WIN32
        /* TCP_MAXSEG 在 Windows 上任何 optname 都返回 WSAENOPROTOOPT，
           SYN 里的 MSS 只能靠改网卡 MTU（nb_curl.set_interface_mtu）。 */
        nb_tcp_note(hd, "MSS(TCP_MAXSEG)");
#else
        v = hd->tcp_mss;
        if(setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, NB_SO_OPTVAL(&v), NB_SO_OPTLEN(&v)) != 0)
            nb_tcp_note(hd, "MSS(TCP_MAXSEG)");
#endif
    }
#ifdef _WIN32
    if(hd->tcp_timestamp >= 0) {
        char b = hd->tcp_timestamp ? 1 : 0;
        if(setsockopt(fd, IPPROTO_TCP, NB_TCP_TIMESTAMPS_OPTNAME,
                      NB_SO_OPTVAL(&b), NB_SO_OPTLEN(&b)) != 0)
            nb_tcp_note(hd, "TCP 时间戳");
    }
#endif
    /* Linux 的 TCP 时间戳没有逐 socket 开关，Python 侧已核对全局 sysctl 是否相符。 */

    return CURL_SOCKOPT_OK;
}

/* 传输期间抓一次 socket 快照。 */
static void nb_tcp_snapshot(CURL* c, HandleData* hd)
{
    curl_socket_t s = CURL_SOCKET_BAD;
    int v;
#ifdef _WIN32
    char info[88];
    DWORD got = 0;
    int vlen;
#else
    char info[256];
    socklen_t vlen;
#endif

    hd->snap_ok = 0;
    if(!c || curl_easy_getinfo(c, CURLINFO_ACTIVESOCKET, &s) != CURLE_OK
       || s == CURL_SOCKET_BAD)
        return;

    v = -1;
    vlen = (int)sizeof(v);
#ifdef _WIN32
    if(getsockopt(s, IPPROTO_IP, IP_TTL, NB_SO_OPTVAL_RW(&v), &vlen) == 0)
        hd->snap_ttl = v;
    v = -1; vlen = (int)sizeof(v);
    if(getsockopt(s, SOL_SOCKET, SO_RCVBUF, NB_SO_OPTVAL_RW(&v), &vlen) == 0)
        hd->snap_rcvbuf = v;
    /* SIO_TCP_INFO + TCP_INFO_v0（88 字节）：Mss@4、TimestampsEnabled@16、RcvBuf@44。
       这里的 RcvBuf 是应用**设定值**（不是内核双倍化后的值）。 */
    memset(info, 0, sizeof(info));
    if(WSAIoctl(s, NB_SIO_TCP_INFO, NULL, 0, info, sizeof(info),
                &got, NULL, NULL) == 0 && got >= 48) {
        unsigned long mss = 0, rcvbuf = 0;
        memcpy(&mss, info + 4, 4);
        memcpy(&rcvbuf, info + 44, 4);
        hd->snap_mss = (int)mss;
        hd->snap_rcvbuf = (int)rcvbuf;
        hd->snap_timestamp = info[16] ? 1 : 0;
    }
#else
    if(getsockopt(s, IPPROTO_IP, IP_TTL, NB_SO_OPTVAL_RW(&v), &vlen) == 0)
        hd->snap_ttl = v;
    /* Linux 的 SO_RCVBUF 回读是内核**双倍化**过的值，Python 侧会 // 2。 */
    v = -1; vlen = (socklen_t)sizeof(v);
    if(getsockopt(s, SOL_SOCKET, SO_RCVBUF, NB_SO_OPTVAL_RW(&v), &vlen) == 0)
        hd->snap_rcvbuf = v;
    /* TCP_MAXSEG 回读是"有效发送 MSS"：对端带 TS 时比 SYN 字段少 12，
       建连后还可能被 PMTU 改写，Python 侧比对时留容差。 */
    v = -1; vlen = (socklen_t)sizeof(v);
    if(getsockopt(s, IPPROTO_TCP, TCP_MAXSEG, NB_SO_OPTVAL_RW(&v), &vlen) == 0)
        hd->snap_mss = v;
    /* TCP_INFO：byte5 bit0 = 对端是否回 TS，byte6 高 4 位 = rcv_wscale
       （snd/rcv 两个 4 位位域合占一字节，按 int 解析会得到鬼值）。 */
    memset(info, 0, sizeof(info));
    vlen = (socklen_t)sizeof(info);
    if(getsockopt(s, IPPROTO_TCP, TCP_INFO, NB_SO_OPTVAL_RW(info), &vlen) == 0 && vlen > 6) {
        hd->snap_wscale = (int)(((unsigned char)info[6]) >> 4);
        hd->snap_timestamp = (((unsigned char)info[5]) & 0x01) ? 1 : 0;
    }
#endif
    hd->snap_ok = 1;
}

/* ================================================================== */
/* 回调                                                                */
/* ================================================================== */
static size_t nb_write_cb(char* ptr, size_t size, size_t nmemb, void* ud)
{
    HandleData* hd = (HandleData*)ud;
    size_t n = size * nmemb;
    if(!hd)
        return 0;
    return nb_buf_append(&hd->body, ptr, n) ? n : 0;
}

static size_t nb_header_cb(char* ptr, size_t size, size_t nmemb, void* ud)
{
    HandleData* hd = (HandleData*)ud;
    size_t n = size * nmemb;
    if(!hd)
        return 0;
    /* 趁连接还活着抓一次 socket 快照（perform 之后就晚了）。
       只在本次真的新建过连接时才抓：复用时 sockopt 回调不触发，
       此时去读很可能读到已被系统回收的 fd。 */
    if(hd->tcp_enabled && hd->tcp_sockopt_ran && !hd->snap_ok)
        nb_tcp_snapshot((CURL*)hd->owner, hd);
    return nb_buf_append(&hd->head, ptr, n) ? n : 0;
}

/* ================================================================== */
/* 全局初始化                                                          */
/* ================================================================== */
static int g_inited = 0;

int nb_global_init(void)
{
    if(g_inited)
        return 0;
    if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK)
        return -1;
    g_inited = 1;
    return 0;
}

void nb_global_cleanup(void)
{
    if(g_inited) {
        curl_global_cleanup();
        g_inited = 0;
    }
}

/* 内部：把基础回调与默认项挂到 handle 上（init 与 reset 后都要做） */
static void nb_attach_defaults(CURL* c, HandleData* hd)
{
    curl_easy_setopt(c, CURLOPT_PRIVATE, hd);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, nb_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, hd);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, nb_header_cb);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, hd);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_TCP_KEEPALIVE, 1L);
    /* 默认跟随重定向、自动解压；HTTP 版本默认 2TLS（对齐浏览器） */
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 30L);
    curl_easy_setopt(c, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(c, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);
}

nb_easy* easy_init(void)
{
    CURL* c;
    HandleData* hd;

    if(!g_inited)
        nb_global_init();

    c = curl_easy_init();
    if(!c)
        return NULL;

    hd = (HandleData*)calloc(1, sizeof(HandleData));
    if(!hd) {
        curl_easy_cleanup(c);
        return NULL;
    }
    hd->owner = (void*)c;
    nb_tcp_state_reset(hd);
    nb_attach_defaults(c, hd);
    return (nb_easy*)c;
}

void easy_cleanup(nb_easy* e)
{
    CURL* c = (CURL*)e;
    HandleData* hd;
    if(!c)
        return;
    hd = nb_hd(e);
    curl_easy_setopt(c, CURLOPT_PRIVATE, NULL);
    curl_easy_cleanup(c);
    nb_hd_release(hd);
}

void easy_reset(nb_easy* e)
{
    CURL* c = (CURL*)e;
    HandleData* hd;
    if(!c)
        return;
    hd = nb_hd(e);

    curl_easy_reset(c);   /* 连接缓存保留在 handle 上，不受影响 */

    if(hd) {
        if(hd->headers) {
            curl_slist_free_all(hd->headers);
            hd->headers = NULL;
        }
        if(hd->resolve) {
            curl_slist_free_all(hd->resolve);
            hd->resolve = NULL;
        }
        free(hd->post_body);
        hd->post_body = NULL;
        hd->post_len = 0;
        free(hd->method);
        hd->method = NULL;
        nb_buf_shrink(&hd->body);
        nb_buf_shrink(&hd->head);
        /* curl_easy_reset 已把所有 setopt 清掉（包括 slist option 持有的指针），
           这里只释放我们托管的 slist 内存本身。 */
        nb_free_opt_slists(hd);
        /* curl_easy_reset 已经把 SOCKOPTFUNCTION 清掉了，这里必须同步清画像状态，
           否则下一次 perform 会以为回调还在、拿到脏快照。 */
        nb_tcp_state_reset(hd);
        nb_attach_defaults(c, hd);
    }
}

/* ================================================================== */
/* 指纹：内置预设                                                       */
/* ================================================================== */
int easy_set_impersonate(nb_easy* e, const char* target, int default_headers)
{
    if(!e || !target)
        return -1;
    return (int)curl_easy_impersonate((CURL*)e, target, default_headers ? 1 : 0);
}

int easy_impersonate_exists(const char* target)
{
    CURL* probe;
    CURLcode rc;
    if(!target)
        return 0;
    probe = curl_easy_init();
    if(!probe)
        return 0;
    rc = curl_easy_impersonate(probe, target, 0);
    curl_easy_cleanup(probe);
    return rc == CURLE_OK ? 1 : 0;
}

/* ================================================================== */
/* 指纹：运行时自定义                                                   */
/* ================================================================== */
int nb_fingerprint_size(void)
{
    return (int)sizeof(nb_fingerprint);
}

int easy_apply_fingerprint(nb_easy* e, const nb_fingerprint* fp)
{
    CURL* c = (CURL*)e;
    CURLcode rc;

    if(!c || !fp)
        return -1;

    /* ---- TLS ---- */
    if(fp->ciphers) {
        rc = curl_easy_setopt(c, CURLOPT_SSL_CIPHER_LIST, fp->ciphers);
        if(rc) return (int)rc;
    }
    if(fp->tls13_ciphers) {
        rc = curl_easy_setopt(c, CURLOPT_TLS13_CIPHERS, fp->tls13_ciphers);
        if(rc) return (int)rc;
    }
    if(fp->curves) {
        rc = curl_easy_setopt(c, CURLOPT_SSL_EC_CURVES, fp->curves);
        if(rc) return (int)rc;
    }
    if(fp->sig_hash_algs) {
        rc = curl_easy_setopt(c, CURLOPT_SSL_SIGNATURE_ALGORITHMS, fp->sig_hash_algs);
        if(rc) return (int)rc;
    }
    if(fp->extension_order) {
        rc = curl_easy_setopt(c, CURLOPT_TLS_EXTENSION_ORDER, fp->extension_order);
        if(rc) return (int)rc;
    }
    if(fp->cert_compression) {
        rc = curl_easy_setopt(c, CURLOPT_SSL_CERT_COMPRESSION, fp->cert_compression);
        if(rc) return (int)rc;
    }
    if(fp->delegated_credentials) {
        rc = curl_easy_setopt(c, CURLOPT_TLS_DELEGATED_CREDENTIALS, fp->delegated_credentials);
        if(rc) return (int)rc;
    }
    if(fp->trust_anchors) {
        rc = curl_easy_setopt(c, CURLOPT_TLS_TRUST_ANCHORS, fp->trust_anchors);
        if(rc) return (int)rc;
    }
    if(fp->ssl_version != -1) {
        rc = curl_easy_setopt(c, CURLOPT_SSLVERSION, (long)fp->ssl_version);
        if(rc) return (int)rc;
    }
    if(fp->tls_grease != -1) {
        rc = curl_easy_setopt(c, CURLOPT_TLS_GREASE, (long)fp->tls_grease);
        if(rc) return (int)rc;
    }
    if(fp->tls_grease_sigalgs != -1) {
        rc = curl_easy_setopt(c, CURLOPT_TLS_GREASE_SIGALGS, (long)fp->tls_grease_sigalgs);
        if(rc) return (int)rc;
    }
    if(fp->permute_extensions != -1) {
        rc = curl_easy_setopt(c, CURLOPT_SSL_PERMUTE_EXTENSIONS, (long)fp->permute_extensions);
        if(rc) return (int)rc;
    }
    if(fp->signed_cert_timestamps != -1) {
        rc = curl_easy_setopt(c, CURLOPT_TLS_SIGNED_CERT_TIMESTAMPS, (long)fp->signed_cert_timestamps);
        if(rc) return (int)rc;
    }
    if(fp->status_request != -1) {
        rc = curl_easy_setopt(c, CURLOPT_TLS_STATUS_REQUEST, (long)fp->status_request);
        if(rc) return (int)rc;
    }
    if(fp->enable_alps != -1) {
        rc = curl_easy_setopt(c, CURLOPT_SSL_ENABLE_ALPS, (long)fp->enable_alps);
        if(rc) return (int)rc;
    }
    if(fp->use_new_alps_codepoint != -1) {
        rc = curl_easy_setopt(c, CURLOPT_TLS_USE_NEW_ALPS_CODEPOINT, (long)fp->use_new_alps_codepoint);
        if(rc) return (int)rc;
    }
    if(fp->record_size_limit != -1) {
        rc = curl_easy_setopt(c, CURLOPT_TLS_RECORD_SIZE_LIMIT, (long)fp->record_size_limit);
        if(rc) return (int)rc;
    }
    if(fp->key_shares_limit != -1) {
        rc = curl_easy_setopt(c, CURLOPT_TLS_KEY_SHARES_LIMIT, (long)fp->key_shares_limit);
        if(rc) return (int)rc;
    }

    /* ---- HTTP/2 ---- */
    if(fp->http2_settings) {
        rc = curl_easy_setopt(c, CURLOPT_HTTP2_SETTINGS, fp->http2_settings);
        if(rc) return (int)rc;
    }
    if(fp->http2_window_update != -1) {
        rc = curl_easy_setopt(c, CURLOPT_HTTP2_WINDOW_UPDATE, (long)fp->http2_window_update);
        if(rc) return (int)rc;
    }
    if(fp->http2_pseudo_headers_order) {
        rc = curl_easy_setopt(c, CURLOPT_HTTP2_PSEUDO_HEADERS_ORDER, fp->http2_pseudo_headers_order);
        if(rc) return (int)rc;
    }
    if(fp->http2_streams) {
        rc = curl_easy_setopt(c, CURLOPT_HTTP2_STREAMS, fp->http2_streams);
        if(rc) return (int)rc;
    }
    if(fp->http2_no_priority != -1) {
        rc = curl_easy_setopt(c, CURLOPT_HTTP2_NO_PRIORITY, (long)fp->http2_no_priority);
        if(rc) return (int)rc;
    }
    if(fp->stream_weight != -1) {
        rc = curl_easy_setopt(c, CURLOPT_STREAM_WEIGHT, (long)fp->stream_weight);
        if(rc) return (int)rc;
    }
    if(fp->stream_exclusive != -1) {
        rc = curl_easy_setopt(c, CURLOPT_STREAM_EXCLUSIVE, (long)fp->stream_exclusive);
        if(rc) return (int)rc;
    }

    /* ---- HTTP ---- */
    if(fp->header_order) {
        rc = curl_easy_setopt(c, CURLOPT_HTTPHEADER_ORDER, fp->header_order);
        if(rc) return (int)rc;
    }
    if(fp->split_cookies != -1) {
        rc = curl_easy_setopt(c, CURLOPT_SPLIT_COOKIES, (long)fp->split_cookies);
        if(rc) return (int)rc;
    }

    /* ---- 末尾追加字段（见 nb_curl_bridge.h 的 ABI 约定） ---- */
    if(fp->http2_headers_priority != -1) {
        rc = curl_easy_setopt(c, CURLOPT_HTTP2_HEADERS_PRIORITY,
                              (long)fp->http2_headers_priority);
        if(rc) return (int)rc;
    }

    return 0;
}

/* ================================================================== */
/* 逐项设置                                                            */
/* ================================================================== */
int easy_set_url(nb_easy* e, const char* url)
{
    if(!e) return -1;
    return (int)curl_easy_setopt((CURL*)e, CURLOPT_URL, url);
}

int easy_set_method(nb_easy* e, const char* method)
{
    CURL* c = (CURL*)e;
    HandleData* hd = nb_hd(e);
    if(!c || !hd || !method) return -1;

    /* 这里只记录方法，真正的 setopt 统一放到 easy_perform 之前执行。
       原因：CURLOPT_POSTFIELDS 会把 libcurl 的 httpreq 切成 POST，
       若在此处就设好方法，随后 easy_set_body(NULL) 又会把语义改回 POST，
       导致 GET 被当成 POST 发出去（实测会被服务端 405 拒绝）。 */
    free(hd->method);
    hd->method = nb_strdup(method);
    if(!hd->method)
        return -1;
    return 0;
}

/* perform 前统一应用 method + body，顺序敏感：
   1) 先定 body 语义（POSTFIELDS 会隐式切 POST）
   2) 再按方法复位（HTTPGET / NOBODY）
   3) 最后设 CUSTOMREQUEST 方法字符串，确保不被前面的 setopt 覆盖 */
static void nb_apply_request(CURL* c, HandleData* hd)
{
    const char* m = hd->method ? hd->method : "GET";
    int is_post = (strcmp(m, "POST") == 0);
    int is_head = (strcmp(m, "HEAD") == 0);

    if(hd->post_len > 0) {
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, hd->post_body);
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)hd->post_len);
    }
    else if(is_post) {
        /* 空 body 的 POST：仍然要发 Content-Length: 0 */
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, "");
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, 0L);
    }
    else {
        /* 无 body：清掉 POST 状态并复位为 GET 语义，避免被当成 POST */
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, NULL);
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, 0L);
        curl_easy_setopt(c, CURLOPT_HTTPGET, 1L);
    }

    curl_easy_setopt(c, CURLOPT_NOBODY, is_head ? 1L : 0L);
    curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, m);
}

/* 多行文本头 -> slist */
static struct curl_slist* nb_slist_from_blob(const char* blob)
{
    struct curl_slist* list = NULL;
    const char* p = blob;
    while(*p) {
        const char* nl = strpbrk(p, "\r\n");
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if(len > 0) {
            char* line = (char*)malloc(len + 1);
            if(!line) {
                curl_slist_free_all(list);
                return NULL;
            }
            memcpy(line, p, len);
            line[len] = '\0';
            list = curl_slist_append(list, line);
            free(line);
            if(!list)
                return NULL;
        }
        if(!nl)
            break;
        p = nl + 1;
        while(*p == '\r' || *p == '\n')
            p++;
    }
    return list;
}

int easy_set_headers(nb_easy* e, const char* headers)
{
    CURL* c = (CURL*)e;
    HandleData* hd = nb_hd(e);
    struct curl_slist* list = NULL;

    if(!c || !hd) return -1;

    if(hd->headers) {
        curl_slist_free_all(hd->headers);
        hd->headers = NULL;
    }
    if(headers && *headers) {
        list = nb_slist_from_blob(headers);
        if(!list)
            return -1;
    }
    hd->headers = list;
    return (int)curl_easy_setopt(c, CURLOPT_HTTPHEADER, list);
}

int easy_set_header_lines(nb_easy* e, const char* const* lines, int count)
{
    CURL* c = (CURL*)e;
    HandleData* hd = nb_hd(e);
    struct curl_slist* list = NULL;
    int i;

    if(!c || !hd) return -1;

    if(hd->headers) {
        curl_slist_free_all(hd->headers);
        hd->headers = NULL;
    }
    for(i = 0; i < count; ++i) {
        if(lines[i] && lines[i][0]) {
            list = curl_slist_append(list, lines[i]);
            if(!list)
                return -1;
        }
    }
    hd->headers = list;
    return (int)curl_easy_setopt(c, CURLOPT_HTTPHEADER, list);
}

int easy_set_cookies(nb_easy* e, const char* cookies)
{
    if(!e) return -1;
    return (int)curl_easy_setopt((CURL*)e, CURLOPT_COOKIE, cookies);
}

int easy_set_cookie_engine(nb_easy* e, int enable)
{
    if(!e) return -1;
    /* 传空文件名即开启内存 cookie 引擎 */
    return (int)curl_easy_setopt((CURL*)e, CURLOPT_COOKIEFILE, enable ? "" : NULL);
}

int easy_set_cookie_list(nb_easy* e, const char* cookie)
{
    if(!e) return -1;
    return (int)curl_easy_setopt((CURL*)e, CURLOPT_COOKIELIST, cookie);
}

int easy_get_cookies(nb_easy* e, char** out)
{
    struct curl_slist* list = NULL;
    struct curl_slist* it;
    nb_buf b;
    memset(&b, 0, sizeof(b));
    if(out) *out = NULL;
    if(!e) return -1;
    if(curl_easy_getinfo((CURL*)e, CURLINFO_COOKIELIST, &list) != CURLE_OK)
        return -1;
    for(it = list; it; it = it->next) {
        if(it->data) {
            nb_buf_append(&b, it->data, strlen(it->data));
            nb_buf_append(&b, "\n", 1);
        }
    }
    curl_slist_free_all(list);
    if(out)
        *out = nb_strdup(b.data ? b.data : "");
    nb_buf_free(&b);
    return 0;
}

int easy_set_body(nb_easy* e, const char* body, int len)
{
    CURL* c = (CURL*)e;
    HandleData* hd = nb_hd(e);
    if(!c || !hd) return -1;

    free(hd->post_body);
    hd->post_body = NULL;
    hd->post_len = 0;

    if(body && len > 0) {
        hd->post_body = (char*)malloc((size_t)len + 1);
        if(!hd->post_body)
            return -1;
        memcpy(hd->post_body, body, (size_t)len);
        hd->post_body[len] = '\0';
        hd->post_len = (size_t)len;
    }
    /* 实际的 POSTFIELDS setopt 由 nb_apply_request 在 perform 前完成 */
    return 0;
}

int easy_set_timeout(nb_easy* e, long ms)
{
    if(!e) return -1;
    return (int)curl_easy_setopt((CURL*)e, CURLOPT_TIMEOUT_MS, ms);
}

int easy_set_connect_timeout(nb_easy* e, long ms)
{
    if(!e) return -1;
    return (int)curl_easy_setopt((CURL*)e, CURLOPT_CONNECTTIMEOUT_MS, ms);
}

int easy_set_verify(nb_easy* e, int verify, const char* ca_path)
{
    CURL* c = (CURL*)e;
    if(!c) return -1;
    if(verify) {
        if(ca_path && *ca_path)
            curl_easy_setopt(c, CURLOPT_CAINFO, ca_path);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
        return (int)curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    }
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    return (int)curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
}

int easy_set_http_version(nb_easy* e, int version)
{
    long v;
    if(!e) return -1;
    switch(version) {
    case 10: v = CURL_HTTP_VERSION_1_0; break;
    case 11: v = CURL_HTTP_VERSION_1_1; break;
    case 20: v = CURL_HTTP_VERSION_2_0; break;
    case 21: v = CURL_HTTP_VERSION_2TLS; break;
    case 22: v = CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE; break;
    case 30: v = CURL_HTTP_VERSION_3; break;
    case 31: v = CURL_HTTP_VERSION_3ONLY; break;
    default: v = CURL_HTTP_VERSION_NONE; break;
    }
    return (int)curl_easy_setopt((CURL*)e, CURLOPT_HTTP_VERSION, v);
}

int easy_set_proxy(nb_easy* e, const char* proxy)
{
    if(!e) return -1;
    /* 空串是"显式禁用代理"（CURLOPT_PROXY="" 会连环境变量一起屏蔽）；
       NULL 才是"未设置、跟随环境变量"。 */
    return (int)curl_easy_setopt((CURL*)e, CURLOPT_PROXY, proxy ? proxy : NULL);
}

int easy_set_resolve(nb_easy* e, const char* const* entries, int count)
{
    CURL* c = (CURL*)e;
    HandleData* hd = nb_hd(e);
    struct curl_slist* list = NULL;
    struct curl_slist* old;
    int i;

    if(!c || !hd || count < 0 || (count > 0 && !entries))
        return -1;

    for(i = 0; i < count; i++) {
        struct curl_slist* next = curl_slist_append(list, entries[i]);
        if(!next) {
            curl_slist_free_all(list);
            return -1;
        }
        list = next;
    }

    /* CURLOPT_RESOLVE 只保存指针（lib/setopt.c: s->resolve = slist），
       条目必须活到 handle 结束，所以由 HandleData 持有。 */
    old = hd->resolve;
    hd->resolve = list;
    if(old)
        curl_slist_free_all(old);

    return (int)curl_easy_setopt(c, CURLOPT_RESOLVE, list);
}

int easy_set_userpwd(nb_easy* e, const char* userpwd)
{
    if(!e) return -1;
    return (int)curl_easy_setopt((CURL*)e, CURLOPT_USERPWD, userpwd);
}

int easy_set_redirect(nb_easy* e, int follow, int max_redirs)
{
    CURL* c = (CURL*)e;
    if(!c) return -1;
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, follow ? 1L : 0L);
    return (int)curl_easy_setopt(c, CURLOPT_MAXREDIRS, (long)max_redirs);
}

int easy_set_verbose(nb_easy* e, int on)
{
    if(!e) return -1;
    return (int)curl_easy_setopt((CURL*)e, CURLOPT_VERBOSE, on ? 1L : 0L);
}

int easy_set_fresh_connect(nb_easy* e, int on)
{
    if(!e) return -1;
    return (int)curl_easy_setopt((CURL*)e, CURLOPT_FRESH_CONNECT, on ? 1L : 0L);
}

/* ------------------------------------------------------------------ */
/* TCP 层画像                                                          */
/* ------------------------------------------------------------------ */
int easy_set_tcp_shape(nb_easy* e, const nb_tcp_shape* st)
{
    CURL* c = (CURL*)e;
    HandleData* hd = nb_hd(e);

    if(!c || !hd)
        return -1;

    hd->tcp_err[0] = '\0';
    hd->tcp_err_set = 0;

    if(!st) {
        /* 取消画像：摘掉回调，本机默认窗口 / wscale 原样留着 */
        nb_tcp_state_reset(hd);
        return (int)curl_easy_setopt(c, CURLOPT_SOCKOPTFUNCTION, NULL);
    }

    hd->tcp_enabled = 1;
    hd->tcp_ttl = st->ttl;
    hd->tcp_mss = st->mss;
    hd->tcp_window = st->window;
    hd->tcp_wscale = st->wscale;
    hd->tcp_rcvbuf = st->rcvbuf;
    hd->tcp_timestamp = st->timestamp;

    curl_easy_setopt(c, CURLOPT_SOCKOPTDATA, hd);
    return (int)curl_easy_setopt(c, CURLOPT_SOCKOPTFUNCTION, nb_sockopt_cb);
}

const char* easy_get_tcp_shape_error(nb_easy* e)
{
    HandleData* hd = nb_hd(e);
    if(!hd || !hd->tcp_err_set)
        return NULL;
    return hd->tcp_err;
}

int easy_check_tcp_shape(nb_easy* e, nb_tcp_shape_actual* out)
{
    HandleData* hd = nb_hd(e);
    if(!hd || !out || !hd->snap_ok)
        return -1;
    out->ttl = hd->snap_ttl;
    out->mss = hd->snap_mss;
    out->wscale = hd->snap_wscale;
    out->window = hd->snap_window;
    out->rcvbuf = hd->snap_rcvbuf;
    out->timestamp = hd->snap_timestamp;
    return 0;
}

int _curl_easy_setopt(nb_easy* e, int option, void* param)
{
    CURL* c = (CURL*)e;
    if(!c)
        return -1;
    if(option < CURLOPTTYPE_OBJECTPOINT)
        return (int)curl_easy_setopt(c, (CURLoption)option, *(long*)param);
    if(CURLOPTTYPE_OFF_T <= option && option < CURLOPTTYPE_BLOB)
        return (int)curl_easy_setopt(c, (CURLoption)option, *(curl_off_t*)param);
    return (int)curl_easy_setopt(c, (CURLoption)option, param);
}

/* ================================================================== */
/* 通用 setopt 直传（按编号范围分派）                                 */
/* ================================================================== */
int easy_set_option_long(nb_easy* e, int option, long value)
{
    CURL* c = (CURL*)e;
    if(!c)
        return -1;
    if(option < 0 || option >= CURLOPTTYPE_OBJECTPOINT)
        return -2;  /* 不是 long 类 option */
    return (int)curl_easy_setopt(c, (CURLoption)option, value);
}

int easy_set_option_string(nb_easy* e, int option, const char* value)
{
    CURL* c = (CURL*)e;
    if(!c)
        return -1;
    if(option < CURLOPTTYPE_OBJECTPOINT || option >= CURLOPTTYPE_FUNCTIONPOINT)
        return -2;  /* 不是 string/object 类 option */
    return (int)curl_easy_setopt(c, (CURLoption)option, value);
}

int easy_set_option_slist(nb_easy* e, int option,
                           const char* const* entries, int count)
{
    CURL* c = (CURL*)e;
    HandleData* hd = nb_hd(e);
    struct curl_slist* list = NULL;
    struct curl_slist* old_list = NULL;
    NbOptSlistEntry* slot = NULL;
    int i;

    if(!c || !hd)
        return -1;
    if(option < CURLOPTTYPE_OBJECTPOINT || option >= CURLOPTTYPE_FUNCTIONPOINT)
        return -2;  /* slist option 也落在 10000-19999 区间 */
    if(count < 0 || (count > 0 && !entries))
        return -1;

    for(i = 0; i < count; i++) {
        struct curl_slist* next = curl_slist_append(list, entries[i]);
        if(!next) {
            curl_slist_free_all(list);
            return -1;
        }
        list = next;
    }

    /* 找同 option 的槽位（线性查找：curl_options 直传一般不会用到几十个 slist） */
    for(i = 0; i < hd->n_opt_slists; i++) {
        if(hd->opt_slists[i].option == option) {
            slot = &hd->opt_slists[i];
            break;
        }
    }
    if(!slot) {
        /* 新槽位 */
        NbOptSlistEntry* grown = (NbOptSlistEntry*)realloc(
            hd->opt_slists, sizeof(NbOptSlistEntry) * (hd->n_opt_slists + 1));
        if(!grown) {
            curl_slist_free_all(list);
            return -1;
        }
        hd->opt_slists = grown;
        slot = &hd->opt_slists[hd->n_opt_slists++];
        slot->option = option;
        slot->list = NULL;
    }

    old_list = slot->list;
    slot->list = list;
    if(old_list)
        curl_slist_free_all(old_list);

    return (int)curl_easy_setopt(c, (CURLoption)option, list);
}

int easy_set_option_off(nb_easy* e, int option, long long value)
{
    CURL* c = (CURL*)e;
    if(!c)
        return -1;
    if(option < CURLOPTTYPE_OFF_T || option >= CURLOPTTYPE_BLOB)
        return -2;  /* 不是 off_t 类 option */
    return (int)curl_easy_setopt(c, (CURLoption)option, (curl_off_t)value);
}

/* ================================================================== */
/* WebSocket                                                          */
/* ================================================================== */
int easy_ws_send(nb_easy* e, const char* buf, int len, int flags)
{
    CURL* c = (CURL*)e;
    size_t sent = 0;
    CURLcode rc;
    if(!c)
        return -1;
    if(len < 0 || (len > 0 && !buf))
        return -1;
    rc = curl_ws_send(c, buf ? buf : "", (size_t)len, &sent, 0,
                      (unsigned int)flags);
    if(rc != CURLE_OK)
        return (int)rc;
    if((int)sent != len)
        return -3;  /* 部分发送：调用方按整帧重发 */
    return 0;
}

int easy_ws_recv(nb_easy* e, char* buf, int cap,
                 int* nread, int* oflags,
                 long long* offset, long long* bytesleft)
{
    CURL* c = (CURL*)e;
    const struct curl_ws_frame* meta = NULL;
    size_t got = 0;
    CURLcode rc;

    if(!c)
        return -1;
    if(cap <= 0 || !buf)
        return -1;
    if(nread) *nread = 0;
    if(oflags) *oflags = 0;
    if(offset) *offset = 0;
    if(bytesleft) *bytesleft = 0;

    rc = curl_ws_recv(c, buf, (size_t)cap, &got, &meta);
    if(rc != CURLE_OK)
        return (int)rc;

    if(nread) *nread = (int)got;
    if(meta) {
        if(oflags) *oflags = meta->flags;
        if(offset) *offset = (long long)meta->offset;
        if(bytesleft) *bytesleft = (long long)meta->bytesleft;
    }
    return 0;
}

/* ================================================================== */
/* 执行与信息                                                          */
/* ================================================================== */
/* easy_perform / easy_perform_take 的公共实现。
   take=0：body/headers 复制一份（nb_strndup，老 ABI 语义，handle 缓冲保留复用）；
   take=1：body/headers **整块移交**给调用方，handle 缓冲置空 —— 少一次整块拷贝。
   失败（CURLE_*）时不留残余大缓冲：take 版直接释放，非 take 版按 keep 收缩。 */
static int nb_perform_impl(nb_easy* e, int* status_code, char** body,
                           size_t* body_len, char** headers, size_t* headers_len,
                           char** error_msg, int take)
{
    CURL* c = (CURL*)e;
    HandleData* hd = nb_hd(e);
    CURLcode res;
    long code = 0;

    if(!c || !hd)
        return -1;

    if(status_code) *status_code = 0;
    if(body) *body = NULL;
    if(body_len) *body_len = 0;
    if(headers) *headers = NULL;
    if(headers_len) *headers_len = 0;
    if(error_msg) *error_msg = NULL;

    nb_buf_reset(&hd->body);
    nb_buf_reset(&hd->head);
    hd->snap_ok = 0;
    hd->tcp_sockopt_ran = 0;
    nb_apply_request(c, hd);

    res = curl_easy_perform(c);

    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    if(status_code)
        *status_code = (int)code;

    if(headers) {
        if(take)
            nb_buf_take(&hd->head, headers, headers_len);
        else {
            *headers = nb_strndup(hd->head.data ? hd->head.data : "", hd->head.len);
            if(headers_len) *headers_len = hd->head.len;
        }
    }

    if(res == CURLE_OK) {
        if(body) {
            if(take)
                nb_buf_take(&hd->body, body, body_len);
            else {
                *body = nb_strndup(hd->body.data ? hd->body.data : "", hd->body.len);
                if(body_len) *body_len = hd->body.len;
            }
        }
    }
    else {
        if(error_msg)
            *error_msg = nb_strdup(curl_easy_strerror(res));
        /* 失败：不把可能很大的半截正文留在句柄上，也不复制给调用方 */
        if(take)
            nb_buf_shrink(&hd->body);
    }

    return (int)res;
}

int easy_perform(nb_easy* e, int* status_code, char** body,
                 size_t* body_len, char** headers, size_t* headers_len,
                 char** error_msg)
{
    return nb_perform_impl(e, status_code, body, body_len,
                           headers, headers_len, error_msg, 0);
}

int easy_perform_take(nb_easy* e, int* status_code, char** body,
                      size_t* body_len, char** headers, size_t* headers_len,
                      char** error_msg)
{
    return nb_perform_impl(e, status_code, body, body_len,
                           headers, headers_len, error_msg, 1);
}

/* multi 路径的"准备"：清结果缓冲 + 把 method/body 落到句柄上。
   必须在 nb_multi_add 之前调用（multi 路径不走 easy_perform）。 */
int easy_prepare_request(nb_easy* e)
{
    CURL* c = (CURL*)e;
    HandleData* hd = nb_hd(e);
    if(!c || !hd)
        return -1;
    nb_buf_reset(&hd->body);
    nb_buf_reset(&hd->head);
    hd->snap_ok = 0;
    hd->tcp_sockopt_ran = 0;
    nb_apply_request(c, hd);
    return 0;
}

int easy_take_body(nb_easy* e, char** out, size_t* len)
{
    HandleData* hd = nb_hd(e);
    if(!hd)
        return -1;
    nb_buf_take(&hd->body, out, len);
    return 0;
}

int easy_take_headers(nb_easy* e, char** out, size_t* len)
{
    HandleData* hd = nb_hd(e);
    if(!hd)
        return -1;
    nb_buf_take(&hd->head, out, len);
    return 0;
}

int easy_pause(nb_easy* e, int bitmask)
{
    if(!e)
        return -1;
    return (int)curl_easy_pause((CURL*)e, bitmask);
}

void easy_free_string(char* ptr)
{
    free(ptr);
}

int easy_getinfo_long(nb_easy* e, int info, long* out)
{
    if(!e || !out) return -1;
    return (int)curl_easy_getinfo((CURL*)e, (CURLINFO)info, out);
}

int easy_getinfo_double(nb_easy* e, int info, double* out)
{
    if(!e || !out) return -1;
    return (int)curl_easy_getinfo((CURL*)e, (CURLINFO)info, out);
}

int easy_getinfo_string(nb_easy* e, int info, const char** out)
{
    if(!e || !out) return -1;
    return (int)curl_easy_getinfo((CURL*)e, (CURLINFO)info, out);
}

const char* easy_version(void)
{
    return curl_version();
}

const char* easy_strerror(int code)
{
    return curl_easy_strerror((CURLcode)code);
}

/* ================================================================== */
/* 阶段 2：multi 驱动                                                  */
/* ================================================================== */
/*
 * 一个 nb_multi 只由一个所有者线程操作（与放进它的 easy 句柄同属一线程）。
 * 唯一例外是 nb_multi_wakeup：libcurl 明确允许从其它线程调它来打断等待。
 *
 * socket / timer 回调在 nb_multi_init 时一次性挂好，生命周期与 nb_multi 一致，
 * 因此调用方**不需要**保活任何回调对象（这是相对"Python 侧回调"的关键差别）。
 */

typedef struct {
    CURLM*        m;
    nb_sock_info* socks;        /* 槽位数组；fd < 0 表示空槽 */
    int           n_socks;      /* 槽位容量 */
    nb_sock_info* changes;      /* 按回调顺序记录，消费后复用容量 */
    int           n_changes;
    int           changes_cap;
    int           running;      /* 上一次 drive 后的活跃传输数 */
    int           in_callback;  /* >0 = 正在一次会触发 libcurl 回调的调用里
                                   （perform / socket_action / fire_timer / poll /
                                    add / remove）；cleanup 期间不允许 */
    int           broken;       /* 出现致命 CURLMcode 后置位，调用方应丢弃该 multi */
} NbMulti;

static int nb_multi_queue_socket(NbMulti* mm, curl_socket_t s, int what)
{
    nb_sock_info* change;
    if(mm->n_changes == mm->changes_cap) {
        int ncap;
        nb_sock_info* np;
        if(mm->changes_cap > INT_MAX / 2)
            goto broken;
        ncap = mm->changes_cap ? mm->changes_cap * 2 : 16;
        if((size_t)ncap > SIZE_MAX / sizeof(nb_sock_info))
            goto broken;
        np = (nb_sock_info*)realloc(mm->changes,
                                    (size_t)ncap * sizeof(nb_sock_info));
        if(!np)
            goto broken;
        mm->changes = np;
        mm->changes_cap = ncap;
    }
    change = &mm->changes[mm->n_changes++];
    change->fd = (long long)s;
    change->action = what;
    change->_reserved = 0;
    return 0;

broken:
    mm->broken = 1;
    return -1;
}

/* socketp 保存槽位编号 + 1，数组扩容不会使它失效。 */
static int nb_multi_sock_cb(CURL* easy, curl_socket_t s, int what,
                            void* ud, void* socketp)
{
    NbMulti* mm = (NbMulti*)ud;
    int i;
    int slot = -1;
    int free_slot = -1;

    (void)easy;
    if(!mm)
        return 0;
    if(mm->broken)
        return -1;
    if(nb_multi_queue_socket(mm, s, what) != 0)
        return -1;

    if(socketp)
        slot = (int)((uintptr_t)socketp - 1);
    else {
        for(i = 0; i < mm->n_socks; i++) {
            if(mm->socks[i].fd == (long long)s) {
                slot = i;
                break;
            }
            if(free_slot < 0 && mm->socks[i].fd < 0)
                free_slot = i;
        }
    }

    if(what == CURL_POLL_REMOVE) {
        if(slot >= 0) {
            mm->socks[slot].fd = -1;
            mm->socks[slot].action = CURL_POLL_NONE;
        }
        if(curl_multi_assign(mm->m, s, NULL) != CURLM_OK)
            goto broken;
        return 0;
    }

    if(slot < 0) {
        if(free_slot < 0) {
            int ncap;
            nb_sock_info* np;
            if(mm->n_socks > INT_MAX / 2)
                goto broken;
            ncap = mm->n_socks ? mm->n_socks * 2 : 16;
            if((size_t)ncap > SIZE_MAX / sizeof(nb_sock_info))
                goto broken;
            np = (nb_sock_info*)realloc(mm->socks,
                                        (size_t)ncap * sizeof(nb_sock_info));
            if(!np)
                goto broken;
            memset(np + mm->n_socks, 0,
                   (size_t)(ncap - mm->n_socks) * sizeof(nb_sock_info));
            for(i = mm->n_socks; i < ncap; i++)
                np[i].fd = -1;
            free_slot = mm->n_socks;
            mm->socks = np;
            mm->n_socks = ncap;
        }
        slot = free_slot;
    }

    mm->socks[slot].fd = (long long)s;
    mm->socks[slot].action = what;
    if(!socketp && curl_multi_assign(mm->m, s,
                                    (void*)(uintptr_t)(slot + 1)) != CURLM_OK)
        goto broken;
    return 0;

broken:
    mm->broken = 1;
    return -1;
}

/* timer 回调：只保留"libcurl 需要重算定时器"的通知语义。
   超时值**不从这里取**：回调里的相对毫秒值在别的事件之后就无法再换算成到期点
   （libcurl 会用同样的相对值给出一个新的绝对到期点）。调用方一律用
   nb_multi_timer() 现取剩余时间。
   这里也**不能**递归调 socket_action（libcurl 禁止回调内重入），
   由调用方在本轮 drive 返回后调 nb_multi_fire_timer。 */
static int nb_multi_timer_cb(CURLM* m, long timeout_ms, void* ud)
{
    (void)m;
    (void)timeout_ms;
    (void)ud;
    return 0;
}

int nb_multi_abi_version(void)
{
    return 3;
}

nb_multi* nb_multi_init(void)
{
    CURLM* cm;
    NbMulti* mm;
    int i;

    if(!g_inited && nb_global_init() != 0)
        return NULL;

    cm = curl_multi_init();
    if(!cm)
        return NULL;

    mm = (NbMulti*)calloc(1, sizeof(NbMulti));
    if(!mm) {
        curl_multi_cleanup(cm);
        return NULL;
    }
    mm->m = cm;
    mm->n_socks = 16;
    mm->socks = (nb_sock_info*)calloc((size_t)mm->n_socks, sizeof(nb_sock_info));
    if(!mm->socks) {
        curl_multi_cleanup(cm);
        free(mm);
        return NULL;
    }
    for(i = 0; i < mm->n_socks; i++)
        mm->socks[i].fd = -1;

    /* 回调挂不上就宁可不返回这个 multi：没有 socket/timer 事件来源的 multi 会让
       Python 侧静默挂死，返回 NULL 才是"确定失败"。 */
    if(curl_multi_setopt(cm, CURLMOPT_SOCKETFUNCTION, nb_multi_sock_cb) != CURLM_OK
       || curl_multi_setopt(cm, CURLMOPT_SOCKETDATA, mm) != CURLM_OK
       || curl_multi_setopt(cm, CURLMOPT_TIMERFUNCTION, nb_multi_timer_cb) != CURLM_OK
       || curl_multi_setopt(cm, CURLMOPT_TIMERDATA, mm) != CURLM_OK) {
        curl_multi_cleanup(cm);
        free(mm->socks);
        free(mm);
        return NULL;
    }

    return (nb_multi*)mm;
}

void nb_multi_cleanup(nb_multi* m)
{
    NbMulti* mm = (NbMulti*)m;
    if(!mm)
        return;
    if(mm->in_callback) {
        /* 回调期间释放会留下悬空指针：拒绝并标记，交给调用方在回调外重试 */
        mm->broken = 1;
        return;
    }
    /* 仍在 multi 里的 easy **不会**被释放（归 Python 的 _Handle 所有）；
       curl_multi_cleanup 会把它们摘出去。调用方本应先 nb_multi_remove。 */
    curl_multi_cleanup(mm->m);
    free(mm->changes);
    free(mm->socks);
    free(mm);
}

int nb_multi_add(nb_multi* m, nb_easy* e)
{
    NbMulti* mm = (NbMulti*)m;
    CURLMcode rc;
    if(!mm || !e)
        return -1;
    if(mm->broken)
        return -2;
    mm->in_callback++;                  /* add 也会触发 socket/timer 回调 */
    rc = curl_multi_add_handle(mm->m, (CURL*)e);
    mm->in_callback--;
    if(rc != CURLM_OK)
        return -(int)rc;
    /* 回调里（例如 fd 表扩容失败）把 multi 标成 broken 时，这里必须让调用方看到 */
    return mm->broken ? -2 : 0;
}

int nb_multi_remove(nb_multi* m, nb_easy* e)
{
    NbMulti* mm = (NbMulti*)m;
    CURLMcode rc;
    if(!mm || !e)
        return -1;
    mm->in_callback++;                  /* remove 也会触发 socket 回调（REMOVE） */
    rc = curl_multi_remove_handle(mm->m, (CURL*)e);
    mm->in_callback--;
    if(rc != CURLM_OK)
        return -(int)rc;
    /* 摘掉之后 libcurl 会为它用过的 socket 回调 CURL_POLL_REMOVE，
       fd 表随之清理；这里不再额外动表（同一个 fd 可能还归别的 easy）。 */
    return mm->broken ? -2 : 0;
}

int nb_multi_active(nb_multi* m)
{
    NbMulti* mm = (NbMulti*)m;
    if(!mm)
        return -1;
    if(mm->broken)
        return -1;
    return mm->running;
}

int nb_multi_perform(nb_multi* m)
{
    NbMulti* mm = (NbMulti*)m;
    CURLMcode rc;
    int running = 0;

    if(!mm)
        return -1;
    if(mm->broken)
        return -2;

    mm->in_callback++;
    rc = curl_multi_perform(mm->m, &running);
    mm->in_callback--;

    if(rc != CURLM_OK) {
        mm->broken = 1;
        return -(int)rc;
    }
    mm->running = running;
    return mm->broken ? -2 : running;
}

int nb_multi_socket_action(nb_multi* m, long long fd, int ev_bitmask)
{
    NbMulti* mm = (NbMulti*)m;
    CURLMcode rc;
    int running = 0;
    curl_socket_t cs;

    if(!mm)
        return -1;
    if(mm->broken)
        return -2;

    cs = (fd < 0) ? CURL_SOCKET_TIMEOUT : (curl_socket_t)fd;

    mm->in_callback++;
    rc = curl_multi_socket_action(mm->m, cs, ev_bitmask, &running);
    mm->in_callback--;

    if(rc != CURLM_OK) {
        mm->broken = 1;
        return -(int)rc;
    }
    mm->running = running;
    return mm->broken ? -2 : running;
}

int nb_multi_socket_snapshot(nb_multi* m, nb_sock_info* out, int cap, int* total)
{
    NbMulti* mm = (NbMulti*)m;
    int i;
    int n = 0;

    if(!mm || cap < 0 || (cap > 0 && !out))
        return -1;

    for(i = 0; i < mm->n_socks; i++) {
        if(mm->socks[i].fd < 0 || mm->socks[i].action == CURL_POLL_NONE)
            continue;
        if(n < cap)
            out[n] = mm->socks[i];
        n++;
    }
    if(total)
        *total = n;
    return n < cap ? n : cap;
}

int nb_multi_socket_changes(nb_multi* m, nb_sock_info* out, int cap, int* total)
{
    NbMulti* mm = (NbMulti*)m;
    int n;
    if(!mm || cap < 0 || (cap > 0 && !out))
        return -1;
    if(mm->broken)
        return -2;
    n = mm->n_changes;
    if(total)
        *total = n;
    if(!out || cap < n)
        return 0;
    if(n)
        memcpy(out, mm->changes, (size_t)n * sizeof(nb_sock_info));
    mm->n_changes = 0;
    return n;
}

int nb_multi_timer(nb_multi* m, long* out_ms)
{
    NbMulti* mm = (NbMulti*)m;
    CURLMcode rc;
    long ms = -1;

    if(!mm || !out_ms)
        return -1;
    if(mm->broken)
        return -2;

    /* 公开 API curl_multi_timeout()：以"现在"为基准重算剩余毫秒，
       0 = 已到期、-1 = 没有定时器。绝不用 timer 回调里那份相对值 ——
       它代表的是回调那一刻的剩余量，之后其它事件已经把它变成过去时。 */
    rc = curl_multi_timeout(mm->m, &ms);
    if(rc != CURLM_OK) {
        mm->broken = 1;
        return -(int)rc;
    }
    *out_ms = ms;
    return 0;
}

int nb_multi_fire_timer(nb_multi* m)
{
    NbMulti* mm = (NbMulti*)m;
    CURLMcode rc;
    int running = 0;

    if(!mm)
        return -1;
    if(mm->broken)
        return -2;

    mm->in_callback++;
    rc = curl_multi_socket_action(mm->m, CURL_SOCKET_TIMEOUT, 0, &running);
    mm->in_callback--;

    if(rc != CURLM_OK) {
        mm->broken = 1;
        return -(int)rc;
    }
    mm->running = running;
    return mm->broken ? -2 : running;
}

int nb_multi_drain(nb_multi* m, int* msg, int* code, nb_easy** easy_out)
{
    NbMulti* mm = (NbMulti*)m;
    CURLMsg* item;
    int left = 0;

    if(!mm)
        return -1;

    item = curl_multi_info_read(mm->m, &left);
    if(!item)
        return 0;

    if(msg)
        *msg = (int)item->msg;
    if(code)
        *code = (int)item->data.result;
    if(easy_out)
        *easy_out = (nb_easy*)item->easy_handle;
    return 1;
}

int nb_multi_poll(nb_multi* m, long timeout_ms, int* out_numfds)
{
    NbMulti* mm = (NbMulti*)m;
    CURLMcode rc;
    int nfds = 0;

    if(!mm)
        return -1;
    if(mm->broken)
        return -2;

    /* libcurl 的 curl_multi_poll 要求非负 timeout；负值按"不等待"处理，
       绝不做无界等待（头文件里的旧说明已同步修正）。 */
    if(timeout_ms < 0)
        timeout_ms = 0;

    mm->in_callback++;
    rc = curl_multi_poll(mm->m, NULL, 0, (int)timeout_ms, &nfds);
    mm->in_callback--;

    if(out_numfds)
        *out_numfds = nfds;
    if(rc != CURLM_OK) {
        mm->broken = 1;
        return -(int)rc;
    }
    return nfds;
}

int nb_multi_wakeup(nb_multi* m)
{
    NbMulti* mm = (NbMulti*)m;
    if(!mm)
        return -1;
    /* 唯一允许跨线程调用的函数 */
    return (int)curl_multi_wakeup(mm->m);
}

/* 跨平台 poll：把多路 multi 的 socket 并成一次等待。
   Windows 用 WSAPoll（只对 socket 有效，正好符合我们的用途），其余平台用 poll(2)。 */
int nb_poll_sockets(nb_poll_item* items, int count, long timeout_ms)
{
    int i;
    int ready = 0;

    if(count <= 0 || !items)
        return -1;

#ifdef _WIN32
    {
        WSAPOLLFD* fds = (WSAPOLLFD*)malloc((size_t)count * sizeof(WSAPOLLFD));
        int rc;
        if(!fds)
            return -1;
        for(i = 0; i < count; i++) {
            fds[i].fd = (SOCKET)(uintptr_t)items[i].fd;
            fds[i].events = 0;
            if(items[i].events & NB_CSELECT_IN)
                fds[i].events |= POLLRDNORM;
            if(items[i].events & NB_CSELECT_OUT)
                fds[i].events |= POLLWRNORM;
            fds[i].revents = 0;
        }
        rc = WSAPoll(fds, (ULONG)count, (INT)timeout_ms);
        if(rc == SOCKET_ERROR) {
            free(fds);
            return -2;
        }
        for(i = 0; i < count; i++) {
            int r = 0;
            if(fds[i].revents & (POLLRDNORM | POLLIN))
                r |= NB_CSELECT_IN;
            if(fds[i].revents & (POLLWRNORM | POLLOUT))
                r |= NB_CSELECT_OUT;
            if(fds[i].revents & (POLLERR | POLLHUP | POLLNVAL))
                r |= NB_CSELECT_ERR;
            items[i].revents = r;
            if(r)
                ready++;
        }
        free(fds);
        return ready;
    }
#else
    {
        struct pollfd* fds = (struct pollfd*)malloc(
            (size_t)count * sizeof(struct pollfd));
        int rc;
        if(!fds)
            return -1;
        for(i = 0; i < count; i++) {
            fds[i].fd = (int)items[i].fd;
            fds[i].events = 0;
            if(items[i].events & NB_CSELECT_IN)
                fds[i].events |= POLLIN;
            if(items[i].events & NB_CSELECT_OUT)
                fds[i].events |= POLLOUT;
            fds[i].revents = 0;
        }
        rc = poll(fds, (nfds_t)count, (int)timeout_ms);
        if(rc < 0) {
            int err = errno;
            free(fds);
            return (err == EINTR) ? -3 : -2;
        }
        for(i = 0; i < count; i++) {
            int r = 0;
            if(fds[i].revents & POLLIN)
                r |= NB_CSELECT_IN;
            if(fds[i].revents & POLLOUT)
                r |= NB_CSELECT_OUT;
            if(fds[i].revents & (POLLERR | POLLHUP | POLLNVAL))
                r |= NB_CSELECT_ERR;
            items[i].revents = r;
            if(r)
                ready++;
        }
        free(fds);
        return ready;
    }
#endif
}
