/*
 * nb_curl_bridge.h — nb_curl 的稳定 C ABI 桥接层
 *
 * 设计目标：
 *   1. 把 libcurl 的变参 setopt/getinfo 封装成固定签名函数，供 Python ctypes/CFFI 调用。
 *   2. 内置指纹直接转发给 libcurl 的 curl_easy_impersonate()，不在桥接层再维护一份表。
 *   3. 运行时自定义指纹通过 easy_apply_fingerprint() 一次性下发（struct 版，减少跨界调用）。
 *
 * 说明：本文件只暴露本项目要用的 option，不照搬 curl 全枚举。
 */
#ifndef NB_CURL_BRIDGE_H
#define NB_CURL_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#  ifdef NB_BUILD_DLL
#    define NB_API __declspec(dllexport)
#  else
#    define NB_API __declspec(dllimport)
#  endif
#  define NB_CALL __cdecl
#else
#  define NB_API __attribute__((visibility("default")))
#  define NB_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明句柄（内部就是 CURL*，但对外不暴露 libcurl 类型，保持 ABI 稳定） */
typedef void nb_easy;

/* ------------------------------------------------------------------ */
/* 运行时自定义指纹：所有字段都可选，-1 表示"不设置"                    */
/* ------------------------------------------------------------------ */
typedef struct {
    int32_t     struct_size;        /* = sizeof(nb_fingerprint)，用于版本兼容 */

    /* --- TLS --- */
    const char* ciphers;            /* CURLOPT_SSL_CIPHER_LIST (TLS1.2) */
    const char* tls13_ciphers;      /* CURLOPT_TLS13_CIPHERS */
    const char* curves;             /* CURLOPT_SSL_EC_CURVES */
    const char* sig_hash_algs;      /* CURLOPT_SSL_SIGNATURE_ALGORITHMS */
    const char* extension_order;    /* CURLOPT_TLS_EXTENSION_ORDER，如 "0-10-13-16-..." */
    const char* cert_compression;   /* CURLOPT_SSL_CERT_COMPRESSION，如 "brotli" */
    int32_t     ssl_version;        /* CURLOPT_SSLVERSION（含 MAX 位），-1 跳过 */
    int32_t     tls_grease;         /* CURLOPT_TLS_GREASE 0/1 */
    int32_t     tls_grease_sigalgs; /* CURLOPT_TLS_GREASE_SIGALGS 0/1 */
    int32_t     permute_extensions; /* CURLOPT_SSL_PERMUTE_EXTENSIONS 0/1 */
    int32_t     signed_cert_timestamps; /* CURLOPT_TLS_SIGNED_CERT_TIMESTAMPS */
    int32_t     status_request;     /* CURLOPT_TLS_STATUS_REQUEST (OCSP) */
    int32_t     enable_alps;        /* CURLOPT_SSL_ENABLE_ALPS */
    int32_t     use_new_alps_codepoint; /* CURLOPT_TLS_USE_NEW_ALPS_CODEPOINT */
    int32_t     record_size_limit;  /* CURLOPT_TLS_RECORD_SIZE_LIMIT */
    int32_t     key_shares_limit;   /* CURLOPT_TLS_KEY_SHARES_LIMIT */
    const char* delegated_credentials;  /* CURLOPT_TLS_DELEGATED_CREDENTIALS */
    const char* trust_anchors;      /* CURLOPT_TLS_TRUST_ANCHORS；"" = 发送空列表 */

    /* --- HTTP/2 --- */
    const char* http2_settings;     /* CURLOPT_HTTP2_SETTINGS，如 "1:65536;2:0;4:6291456" */
    int32_t     http2_window_update;/* CURLOPT_HTTP2_WINDOW_UPDATE */
    const char* http2_pseudo_headers_order; /* CURLOPT_HTTP2_PSEUDO_HEADERS_ORDER，如 "masp" */
    const char* http2_streams;      /* CURLOPT_HTTP2_STREAMS */
    int32_t     http2_no_priority;  /* CURLOPT_HTTP2_NO_PRIORITY */
    int32_t     stream_weight;      /* CURLOPT_STREAM_WEIGHT */
    int32_t     stream_exclusive;   /* CURLOPT_STREAM_EXCLUSIVE */

    /* --- HTTP --- */
    const char* header_order;       /* CURLOPT_HTTPHEADER_ORDER */
    int32_t     split_cookies;      /* CURLOPT_SPLIT_COOKIES */

    /* --- 追加字段（一律放在结构体末尾，保证旧 .pyd 的偏移不变） ---------- */
    int32_t     http2_headers_priority; /* CURLOPT_HTTP2_HEADERS_PRIORITY：
                                           在 H2 HEADERS 帧里带上已废弃的
                                           RFC 7540 优先级字段（E/依赖/权重），
                                           即 Chrome 的 flags=0x25。0/1 */
} nb_fingerprint;

/* ------------------------------------------------------------------ */
/* 生命周期                                                            */
/* ------------------------------------------------------------------ */
NB_API int  NB_CALL nb_global_init(void);      /* 幂等，返回 0 成功 */
NB_API void NB_CALL nb_global_cleanup(void);

NB_API nb_easy* NB_CALL easy_init(void);
NB_API void     NB_CALL easy_cleanup(nb_easy* e);
NB_API void     NB_CALL easy_reset(nb_easy* e);   /* 清空所有 option 与请求态，保留句柄 */

/* ------------------------------------------------------------------ */
/* 指纹：内置预设                                                       */
/* ------------------------------------------------------------------ */
/* target 形如 "chrome116" / "chrome116:no"；default_headers=1 时附带浏览器默认头 */
NB_API int NB_CALL easy_set_impersonate(nb_easy* e, const char* target, int default_headers);
/* 探测某 target 是否存在：1=存在，0=不存在 */
NB_API int NB_CALL easy_impersonate_exists(const char* target);

/* ------------------------------------------------------------------ */
/* 指纹：运行时自定义                                                   */
/* ------------------------------------------------------------------ */
NB_API int NB_CALL easy_apply_fingerprint(nb_easy* e, const nb_fingerprint* fp);
/* 返回 sizeof(nb_fingerprint)，供 Python 侧校验 ABI 布局一致 */
NB_API int NB_CALL nb_fingerprint_size(void);

/* ------------------------------------------------------------------ */
/* 逐项设置                                                            */
/* ------------------------------------------------------------------ */
NB_API int NB_CALL easy_set_url(nb_easy* e, const char* url);
NB_API int NB_CALL easy_set_method(nb_easy* e, const char* method);
/* 多行文本头，用 \n 或 \r\n 分隔 */
NB_API int NB_CALL easy_set_headers(nb_easy* e, const char* headers);
/* 保序、保重复的二维头（数组版，推荐） */
NB_API int NB_CALL easy_set_header_lines(nb_easy* e, const char* const* lines, int count);
NB_API int NB_CALL easy_set_cookies(nb_easy* e, const char* cookies);      /* CURLOPT_COOKIE */
NB_API int NB_CALL easy_set_cookie_engine(nb_easy* e, int enable);         /* 开启内存 cookie 引擎 */
NB_API int NB_CALL easy_set_cookie_list(nb_easy* e, const char* cookie);   /* CURLOPT_COOKIELIST */
NB_API int NB_CALL easy_get_cookies(nb_easy* e, char** out);               /* 每行一条 */
NB_API int NB_CALL easy_set_body(nb_easy* e, const char* body, int len);
NB_API int NB_CALL easy_set_timeout(nb_easy* e, long ms);
NB_API int NB_CALL easy_set_connect_timeout(nb_easy* e, long ms);
NB_API int NB_CALL easy_set_verify(nb_easy* e, int verify, const char* ca_path);
NB_API int NB_CALL easy_set_http_version(nb_easy* e, int version);
NB_API int NB_CALL easy_set_proxy(nb_easy* e, const char* proxy);
/* DNS 覆盖（对应 CURLOPT_RESOLVE，即 curl 命令行的 --resolve）：
 * 条目格式 "host:port:addr[,addr]"，也可用 "+host:port:addr" 追加、"-host:port" 删除；
 * count=0 表示清空。设置后该 host:port 不再走 DNS 解析。 */
NB_API int NB_CALL easy_set_resolve(nb_easy* e, const char* const* entries, int count);
NB_API int NB_CALL easy_set_userpwd(nb_easy* e, const char* userpwd);
NB_API int NB_CALL easy_set_redirect(nb_easy* e, int follow, int max_redirs);
NB_API int NB_CALL easy_set_verbose(nb_easy* e, int on);
NB_API int NB_CALL easy_set_fresh_connect(nb_easy* e, int on);

/* ------------------------------------------------------------------ */
/* TCP 层画像（JA4T）                                                 */
/* ------------------------------------------------------------------ */
/* 在连接建立**之前**按 socket 设 TCP 层可观测项（CURLOPT_SOCKOPTFUNCTION），
   -1 = 该项不设置。window / wscale 共用同一个 SO_RCVBUF，换算在 Python 侧
   （nb_curl/tcp.py）完成，这里只收算好的 rcvbuf；window/wscale 字段仅用于回读比对。 */
typedef struct {
    int32_t     ttl;        /* IP_TTL */
    int32_t     mss;        /* TCP_MAXSEG（只有 Linux 有；Windows 走网卡 MTU） */
    int32_t     window;     /* 不下发，仅供回读比对 */
    int32_t     wscale;     /* 不下发，仅供回读比对 */
    int32_t     rcvbuf;     /* SO_RCVBUF，window / wscale 的实际落点 */
    int32_t     timestamp;  /* TCP 时间戳 0/1（只有 Windows 能逐 socket） */
} nb_tcp_shape;

/* 传输期间回读到的真实值；-1 = 该平台 / 该时刻读不到 */
typedef struct {
    int32_t     ttl;
    int32_t     mss;
    int32_t     wscale;
    int32_t     window;
    int32_t     rcvbuf;
    int32_t     timestamp;
} nb_tcp_shape_actual;

/* 下发画像。st 为 NULL 或全 -1 = 取消画像（摘掉 sockopt 回调）。 */
NB_API int NB_CALL easy_set_tcp_shape(nb_easy* e, const nb_tcp_shape* st);
/* 上次 perform 期间 socket 层设置失败的原因；没有失败返回 NULL。 */
NB_API const char* NB_CALL easy_get_tcp_shape_error(nb_easy* e);
/* 取传输期间抓到的 socket 快照：0 = 有值，-1 = 本次没建新连接或读不到。 */
NB_API int NB_CALL easy_check_tcp_shape(nb_easy* e, nb_tcp_shape_actual* out);

/* 通用 option 透传（option 为 CURLOPT_* 数值；long/off_t 传指针） */
NB_API int NB_CALL _curl_easy_setopt(nb_easy* e, int option, void* param);

/* ------------------------------------------------------------------ */
/* 按编号范围的通用 setopt 直通                                    */
/* ------------------------------------------------------------------ */
/* curl 的 option 类型由编号范围区分（见 curl.h 的 CURLOPTTYPE_*）：
 *   0     <= opt < 10000  long
 *   10000 <= opt < 20000  字符串 / slist / callback-data（同区间，由调用方保证语义）
 *   20000 <= opt < 30000  回调函数指针（不支持直传）
 *   30000 <= opt < 40000  curl_off_t
 *   40000 <= opt < 50000  blob（不支持直传）
 * 范围外的 option 返回 -2。Python 侧通过 CurlOpt._VTYPE 知道每个 option 的真实类型，
 * 会调用对应的 *_long / *_string / *_slist / *_off；类型传错后果自负。 */
NB_API int NB_CALL easy_set_option_long(nb_easy* e, int option, long value);
NB_API int NB_CALL easy_set_option_string(nb_easy* e, int option, const char* value);
/* slist 类 option：内存由桥接层托管（每个 option 一个槽位，重复设置自动替换并释放旧的；
   handle reset/cleanup 时统一释放）。count=0 表示清空该 option 的列表。 */
NB_API int NB_CALL easy_set_option_slist(nb_easy* e, int option,
                                         const char* const* entries, int count);
NB_API int NB_CALL easy_set_option_off(nb_easy* e, int option, long long value);

/* ------------------------------------------------------------------ */
/* WebSocket                                                        */
/* ------------------------------------------------------------------ */
/* 连接建立：调用方先 _curl_easy_setopt(handle, CURLOPT_CONNECT_ONLY=141, &2L)
 *           再调 easy_perform 完成 ws 握手；之后用下面两个函数收发帧。
 * 帧 flags（与 curl 的 CURLWS_* 一致，见 curl/websockets.h）：
 *   TEXT=1  BINARY=2  CONT=4  CLOSE=8  PING=0x10
 *   OFFSET=0x20（recv 元数据位，不是帧类型）  PONG=0x40（send 位） */
/* 发送一帧。整帧一次性写入；返回 CURLcode，部分发送返回 -3（调用方重发整帧）。 */
NB_API int NB_CALL easy_ws_send(nb_easy* e, const char* buf, int len, int flags);
/* 接收一帧片段。无数据时返回 CURLE_AGAIN(81)。
 * 出参 nread=本次读到的字节数；oflags=帧类型 flags；offset=该片段在帧内的偏移；
 * bytesleft=该帧剩余未读字节数（0 表示帧已读完）。 */
NB_API int NB_CALL easy_ws_recv(nb_easy* e, char* buf, int cap,
                                int* nread, int* oflags,
                                long long* offset, long long* bytesleft);

/* ------------------------------------------------------------------ */
/* 执行与信息                                                          */
/* ------------------------------------------------------------------ */
/* 返回 CURLcode。
 * body/headers 指向 C 层分配的缓冲，len 出参给出**真实字节数**（二进制安全，
 * 不会因响应体含 \0 而被截断）。字符串仍以 \0 结尾，方便当文本用。
 * 调用方用 easy_free_string 释放 body/headers/error_msg。
 * body_len/headers_len 可为 NULL（此时按 \0 截断读取）。 */
NB_API int NB_CALL easy_perform(nb_easy* e, int* status_code,
                                char** body, size_t* body_len,
                                char** headers, size_t* headers_len,
                                char** error_msg);
NB_API void NB_CALL easy_free_string(char* ptr);

NB_API int NB_CALL easy_getinfo_long(nb_easy* e, int info, long* out);
NB_API int NB_CALL easy_getinfo_double(nb_easy* e, int info, double* out);
NB_API int NB_CALL easy_getinfo_string(nb_easy* e, int info, const char** out);

NB_API const char* NB_CALL easy_version(void);
NB_API const char* NB_CALL easy_strerror(int code);

/* ================================================================== */
/* 阶段 2 新增：multi 驱动 + 结果所有权移交（固定签名，无变参）        */
/* ================================================================== */
/*
 * 语义约定（谁在什么时候能调）：
 *   - 一个 nb_multi 与放进它的每个 nb_easy 都有**唯一所有者线程**；
 *     除 nb_multi_wakeup 外，其余函数都不允许跨线程并发调用。
 *   - 传输完成：先 nb_multi_drain 读出完成消息（含 CURLcode）并保存，
 *     再 nb_multi_remove，然后才能读结果 / 释放 handle。
 *   - 取消：同样先 nb_multi_remove 再释放；同一次传输只能收尾一次。
 *   - socket/timer 回调在 nb_multi_init 时一次性挂好，生命周期与 nb_multi 相同，
 *     调用方不需要（也不能）保活任何 Python 对象。
 *   - timer 回调里**不允许**递归调用 socket_action：timeout_ms == 0 时桥接层只置
 *     "待触发"标志，由调用方在本轮 socket_action 返回后调 nb_multi_fire_timer。
 *   - 致命错误（drive 返回负 CURLMcode、socket 回调里 fd 表扩容失败等）会把整个
 *     multi 置为 broken：此后所有 nb_multi_* 返回负值（-2），调用方必须丢弃**这个
 *     multi**（并失败它名下所有在飞传输），不能当成"只有某一个请求失败"。
 */

/* 本次编译的 multi ABI 版本；Python 侧据此确认新老 DLL 是否配套（应为 3）。 */
NB_API int NB_CALL nb_multi_abi_version(void);

/* ---------------- 事件位（与 libcurl / asyncio 的映射由 Python 侧做） ------------- */
#define NB_CSELECT_IN   1
#define NB_CSELECT_OUT  2
#define NB_CSELECT_ERR  4

/* pause 位（与 libcurl 的 CURLPAUSE_* 数值一致） */
#define NB_PAUSE_RECV   1
#define NB_PAUSE_SEND   4
#define NB_PAUSE_ALL    5
#define NB_PAUSE_CONT   0

/* socket 快照条目：fd 为 curl_socket_t 的数值形式；action 为 CURL_POLL_* */
typedef struct {
    long long fd;
    int       action;
    int       _reserved;
} nb_sock_info;

/* poll 条目：调用方填 fd/events（NB_CSELECT_* 位），返回时 revents 为就绪位 */
typedef struct {
    long long fd;
    int       events;
    int       revents;
} nb_poll_item;

/* 不透明 multi 句柄 */
typedef void nb_multi;

/* ---------------- multi 生命周期 ------------------------------------------------ */
NB_API nb_multi* NB_CALL nb_multi_init(void);
/* 释放 multi。仍在 multi 里的句柄**不会**被 cleanup 释放，调用方必须先 remove。 */
NB_API void NB_CALL nb_multi_cleanup(nb_multi* m);

NB_API int NB_CALL nb_multi_add(nb_multi* m, nb_easy* e);
NB_API int NB_CALL nb_multi_remove(nb_multi* m, nb_easy* e);
/* 当前还在 multi 里的 transfers 数（curl 的 running_handles） */
NB_API int NB_CALL nb_multi_active(nb_multi* m);

/* ---------------- 请求准备与结果移交 ------------------------------------------- */
/* 把已记录的 method/body 落到 handle 上并清空结果缓冲。
   **必须在 nb_multi_add 之前调用**（multi 路径不走 easy_perform）。 */
NB_API int NB_CALL easy_prepare_request(nb_easy* e);
/* 结果所有权移交：把 C 累积缓冲直接交给调用方（不再 strdup 整体正文）。
   handle 内缓冲被置空；调用方用 easy_free_string 释放。len 可为 NULL。 */
NB_API int NB_CALL easy_take_body(nb_easy* e, char** out, size_t* len);
NB_API int NB_CALL easy_take_headers(nb_easy* e, char** out, size_t* len);
/* 暂停/继续：bitmask 见 NB_PAUSE_*；返回 CURLcode。 */
NB_API int NB_CALL easy_pause(nb_easy* e, int bitmask);

/* easy_perform 的零额外复制版本：与 easy_perform 同签名，
   唯一区别是 body/headers 直接移交 C 累积缓冲（少一次整块 memcpy）。 */
NB_API int NB_CALL easy_perform_take(nb_easy* e, int* status_code,
                                     char** body, size_t* body_len,
                                     char** headers, size_t* headers_len,
                                     char** error_msg);

/* ---------------- 非阻塞推进 / 完成队列 ---------------------------------------- */
/* 等价 curl_multi_perform；返回活跃传输数，或负的 CURLMcode。 */
NB_API int NB_CALL nb_multi_perform(nb_multi* m);
/* 完成队列排空：一次取一条。返回 1 = 取到、0 = 空、<0 = 错误。
   msg 为 CURLMSG_*；code 为该传输的 CURLcode；easy_out 为对应句柄。 */
NB_API int NB_CALL nb_multi_drain(nb_multi* m, int* msg, int* code, nb_easy** easy_out);

/* ---------------- socket-action 驱动 ------------------------------------------- */
/* ev_bitmask 为 NB_CSELECT_* 组合；返回活跃传输数或负 CURLMcode。 */
NB_API int NB_CALL nb_multi_socket_action(nb_multi* m, long long fd, int ev_bitmask);
/* 导出当前登记的 socket 表：out 可传 NULL 只问数量。
   返回写入条数（<0 为错误）；total 出参给总条数，调用方据此扩容。 */
NB_API int NB_CALL nb_multi_socket_snapshot(nb_multi* m, nb_sock_info* out,
                                            int cap, int* total);
/* 按序消费 socket 变更（action 为 CURL_POLL_*，REMOVE=4）。
   out 为 NULL 或 cap 不足时仅设置 total，不消费、返回 0；容量足够时返回条数并清空。
   snapshot 不影响此队列；broken 返回 -2。 */
NB_API int NB_CALL nb_multi_socket_changes(nb_multi* m, nb_sock_info* out,
                                           int cap, int* total);
/* 剩余定时器毫秒数，以**调用时刻**为基准现算（curl_multi_timeout）：
   0 = 已到期该立刻推进，-1 = 当前没有定时器。
   返回 0 成功，负值为 CURLMcode（multi 已标 broken）。 */
NB_API int NB_CALL nb_multi_timer(nb_multi* m, long* out_ms);
/* 触发一次超时处理（等价 socket_action(fd=超时, 0)）。 */
NB_API int NB_CALL nb_multi_fire_timer(nb_multi* m);

/* ---------------- 阻塞等待（Windows 有界专职驱动 / 通用兜底） ------------------ */
/* 单调 millisecond 超时；timeout_ms 必须非负（负值按 0 处理，不做无界等待）。
   返回就绪 socket 数，或负的 CURLMcode。 */
NB_API int NB_CALL nb_multi_poll(nb_multi* m, long timeout_ms, int* out_numfds);
/* 从其它线程打断 nb_multi_poll / 唤醒事件循环（libcurl curl_multi_wakeup）。 */
NB_API int NB_CALL nb_multi_wakeup(nb_multi* m);

/* 跨平台 poll 原语：把多路 multi 的 socket 并成一次等待。
   返回就绪条目数，或负值（-1 = 参数错、-2 = 系统调用失败、-3 = 被中断）。 */
NB_API int NB_CALL nb_poll_sockets(nb_poll_item* items, int count, long timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* NB_CURL_BRIDGE_H */
