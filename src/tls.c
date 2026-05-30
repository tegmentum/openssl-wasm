// tls interface — blocking TLS client/server via OpenSSL.
//
// Sockets are standard BSD sockets; wasi-libc's shim is expected to
// forward these calls to wasi:sockets. If the host does not grant
// socket access, connect()/accept() return -1 and we surface
// tls-error.internal(errno).
//
// This is best-effort. The full TLS state machine (renegotiation
// triggers, async-handshake edge cases) is deferred. 0-RTT early data,
// session tickets, per-SNI binding fallback, keylog callbacks, ALPN
// server selection — all work "in principle" but are not individually
// exercised.

#include "bindings/openssl.h"
#include "include/support.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define TE_BAD_CONFIG        EXPORTS_OPENSSL_COMPONENT_TLS_TLS_ERROR_BAD_CONFIG
#define TE_HANDSHAKE         EXPORTS_OPENSSL_COMPONENT_TLS_TLS_ERROR_HANDSHAKE_FAILED
#define TE_VERIFY            EXPORTS_OPENSSL_COMPONENT_TLS_TLS_ERROR_VERIFY_FAILED
#define TE_HOSTNAME          EXPORTS_OPENSSL_COMPONENT_TLS_TLS_ERROR_HOSTNAME_MISMATCH
#define TE_PROTOCOL          EXPORTS_OPENSSL_COMPONENT_TLS_TLS_ERROR_PROTOCOL_VERSION
#define TE_IO_CLOSED         EXPORTS_OPENSSL_COMPONENT_TLS_TLS_ERROR_IO_CLOSED
#define TE_WOULD_BLOCK       EXPORTS_OPENSSL_COMPONENT_TLS_TLS_ERROR_WOULD_BLOCK
#define TE_INTERNAL          EXPORTS_OPENSSL_COMPONENT_TLS_TLS_ERROR_INTERNAL

static int proto_version(exports_openssl_component_tls_protocol_t p) {
    switch (p) {
    case 0: return TLS1_2_VERSION;
    case 1: return TLS1_3_VERSION;
    case 2: return DTLS1_2_VERSION;
    default: return 0;
    }
}

// --- keylog buffer (embedded in client/server/listener reps) -------------

typedef struct keylog_buf {
    char **lines;
    size_t len, cap;
} keylog_buf;

// Per-SSL pointer to a keylog_buf. Using SSL ex-data (not SSL_CTX)
// because the listener's CTX is shared across all accepted connections;
// each connection gets its own buffer.
static int keylog_ssl_ex_idx(void) {
    static int idx = -1;
    if (idx == -1) {
        idx = SSL_get_ex_new_index(0, (void *)"keylog", NULL, NULL, NULL);
    }
    return idx;
}

static void keylog_buf_init(keylog_buf *b) {
    b->lines = NULL; b->len = 0; b->cap = 0;
}

static void keylog_buf_clear(keylog_buf *b) {
    for (size_t i = 0; i < b->len; i++) free(b->lines[i]);
    free(b->lines);
    keylog_buf_init(b);
}

static void keylog_buf_append(keylog_buf *b, const char *line) {
    if (!b || !line) return;
    if (b->len == b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 16;
        char **grown = realloc(b->lines, nc * sizeof(char *));
        if (!grown) return;
        b->lines = grown;
        b->cap = nc;
    }
    size_t n = strlen(line);
    char *copy = xmalloc(n + 1);
    memcpy(copy, line, n);
    copy[n] = 0;
    b->lines[b->len++] = copy;
}

static void keylog_cb(const SSL *ssl, const char *line) {
    keylog_buf *b = SSL_get_ex_data(ssl, keylog_ssl_ex_idx());
    keylog_buf_append(b, line);
}

// Drain buffer into WIT list<string>, leaving the buffer empty.
static void keylog_buf_drain_to(keylog_buf *b, openssl_list_string_t *out) {
    out->ptr = xmalloc(b->len > 0 ? b->len * sizeof(openssl_string_t)
                                   : sizeof(openssl_string_t));
    out->len = b->len;
    for (size_t i = 0; i < b->len; i++) {
        size_t n = strlen(b->lines[i]);
        string_take(&out->ptr[i], b->lines[i], n);
        free(b->lines[i]);
    }
    free(b->lines);
    keylog_buf_init(b);
}

// --- helpers -------------------------------------------------------------

static int connect_tcp(const char *host, uint16_t port, int *err_out) {
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
        *err_out = errno;
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) *err_out = errno;
    return fd;
}

static int bind_tcp(const char *host, uint16_t port, int *err_out) {
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
        *err_out = errno; return -1;
    }
    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        int yes = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (bind(fd, p->ai_addr, p->ai_addrlen) == 0 &&
            listen(fd, 16) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) *err_out = errno;
    return fd;
}

static void apply_protocols(SSL_CTX *ctx,
        const exports_openssl_component_tls_protocol_range_t *r) {
    int mn = proto_version(r->min), mx = proto_version(r->max);
    if (mn) SSL_CTX_set_min_proto_version(ctx, mn);
    if (mx) SSL_CTX_set_max_proto_version(ctx, mx);
}

static void apply_ciphers(SSL_CTX *ctx,
        const exports_openssl_component_tls_option_cipher_preferences_t *cp) {
    if (!cp->is_some) return;
    if (cp->val.tls12.is_some) {
        char *s = xmalloc(cp->val.tls12.val.len + 1);
        memcpy(s, cp->val.tls12.val.ptr, cp->val.tls12.val.len);
        s[cp->val.tls12.val.len] = 0;
        SSL_CTX_set_cipher_list(ctx, s);
        free(s);
    }
    if (cp->val.tls13.is_some) {
        char *s = xmalloc(cp->val.tls13.val.len + 1);
        memcpy(s, cp->val.tls13.val.ptr, cp->val.tls13.val.len);
        s[cp->val.tls13.val.len] = 0;
        SSL_CTX_set_ciphersuites(ctx, s);
        free(s);
    }
}

static void apply_groups(SSL_CTX *ctx,
        const openssl_option_string_t *g) {
    if (!g->is_some) return;
    char *s = xmalloc(g->val.len + 1);
    memcpy(s, g->val.ptr, g->val.len);
    s[g->val.len] = 0;
    SSL_CTX_set1_groups_list(ctx, s);
    free(s);
}

// ALPN: wire-format for client offers.
static unsigned char *alpn_wire(
        const exports_openssl_component_tls_option_alpn_offer_t *a,
        size_t *out_len) {
    if (!a->is_some) { *out_len = 0; return NULL; }
    size_t total = 0;
    for (size_t i = 0; i < a->val.protocols.len; i++) {
        total += 1 + a->val.protocols.ptr[i].len;
    }
    unsigned char *buf = xmalloc(total ? total : 1);
    size_t o = 0;
    for (size_t i = 0; i < a->val.protocols.len; i++) {
        size_t n = a->val.protocols.ptr[i].len;
        if (n > 255) { free(buf); *out_len = 0; return NULL; }
        buf[o++] = (unsigned char)n;
        memcpy(buf + o, a->val.protocols.ptr[i].ptr, n);
        o += n;
    }
    *out_len = total;
    return buf;
}

// Populate peer_info from a completed SSL handshake.
static void fill_peer_info(SSL *ssl, exports_openssl_component_tls_peer_info_t *out) {
    memset(out, 0, sizeof(*out));
    int ver = SSL_version(ssl);
    out->protocol = ver == TLS1_3_VERSION ? 1 : (ver == DTLS1_2_VERSION ? 2 : 0);
    const char *cs = SSL_get_cipher_name(ssl);
    string_take(&out->cipher_suite, cs ? cs : "", cs ? strlen(cs) : 0);

    const unsigned char *alpn = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
    if (alpn && alpn_len) {
        out->alpn.is_some = true;
        string_take(&out->alpn.val, (const char *)alpn, alpn_len);
    }

    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (sni && *sni) {
        out->sni.is_some = true;
        string_take(&out->sni.val, sni, strlen(sni));
    }

    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
    int n = chain ? sk_X509_num(chain) : 0;
    out->peer_chain.ptr = xmalloc(n > 0 ? n * sizeof(*out->peer_chain.ptr)
                                         : sizeof(*out->peer_chain.ptr));
    out->peer_chain.len = (size_t)(n > 0 ? n : 0);
    for (int i = 0; i < n; i++) {
        X509 *c = sk_X509_value(chain, i);
        X509_up_ref(c);
        out->peer_chain.ptr[i] = exports_openssl_component_x509_certificate_new(
            (exports_openssl_component_x509_certificate_t *)c);
    }

    out->resumed = SSL_session_reused(ssl) != 0;
    const char *grp = SSL_get0_group_name(ssl);
    if (grp) {
        out->group.is_some = true;
        string_take(&out->group.val, grp, strlen(grp));
    }
}

// --- client --------------------------------------------------------------

typedef struct client_rep {
    SSL_CTX *ctx;
    SSL *ssl;
    int fd;
    keylog_buf keylog;     /* non-empty iff cfg->keylog == true */
} client_rep;

bool exports_openssl_component_tls_static_client_connect(
        openssl_string_t *host, uint16_t port,
        exports_openssl_component_tls_client_config_t *cfg,
        exports_openssl_component_tls_own_client_t *ret,
        exports_openssl_component_tls_tls_error_t *err) {
    // DTLS 1.2 is in the WIT enum but not implemented in the component:
    // we'd need BIO_s_datagram + UDP sockets + DTLS_client_method, all of
    // which depend on wasi:sockets UDP which isn't smoke-tested here.
    // Reject cleanly rather than silently fall back to TLS.
    if (cfg->protocols.min == 2 || cfg->protocols.max == 2) {
        err->tag = TE_PROTOCOL;
        err->val.internal = 0;
        return false;
    }
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { err->tag = TE_BAD_CONFIG; return false; }
    apply_protocols(ctx, &cfg->protocols);
    apply_ciphers(ctx, &cfg->ciphers);
    apply_groups(ctx, &cfg->groups);

    SSL_CTX_set_verify(ctx,
        cfg->verify == 0 ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, NULL);
    if (cfg->trust.is_some) {
        X509_STORE *s = (X509_STORE *)
            exports_openssl_component_x509_store_rep(cfg->trust.val);
        X509_STORE_up_ref(s);  /* set_cert_store takes ownership without upref */
        SSL_CTX_set_cert_store(ctx, s);
    }
    if (cfg->client_cert.is_some) {
        SSL_CTX_use_certificate(ctx,
            (X509 *)exports_openssl_component_x509_certificate_rep(cfg->client_cert.val));
    }
    if (cfg->client_key.is_some) {
        SSL_CTX_use_PrivateKey(ctx,
            (EVP_PKEY *)exports_openssl_component_pkey_pkey_rep(cfg->client_key.val));
    }
    if (cfg->keylog) {
        SSL_CTX_set_keylog_callback(ctx, keylog_cb);
    }

    size_t alpn_len = 0;
    unsigned char *alpn = alpn_wire(&cfg->alpn, &alpn_len);
    if (alpn) {
        SSL_CTX_set_alpn_protos(ctx, alpn, (unsigned int)alpn_len);
        free(alpn);
    }

    char *hostnul = xmalloc(host->len + 1);
    memcpy(hostnul, host->ptr, host->len);
    hostnul[host->len] = 0;

    int ioerr = 0;
    int fd = connect_tcp(hostnul, port, &ioerr);
    if (fd < 0) {
        SSL_CTX_free(ctx);
        free(hostnul);
        err->tag = TE_IO_CLOSED; err->val.internal = (uint64_t)ioerr;
        return false;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        close(fd); SSL_CTX_free(ctx); free(hostnul);
        err->tag = TE_BAD_CONFIG; return false;
    }
    // Install the keylog ex-data before SSL_connect so the callback has
    // somewhere to write during handshake.
    keylog_buf *pre_keylog = NULL;
    if (cfg->keylog) {
        pre_keylog = xmalloc(sizeof(*pre_keylog));
        keylog_buf_init(pre_keylog);
        SSL_set_ex_data(ssl, keylog_ssl_ex_idx(), pre_keylog);
    }
    if (cfg->server_name.is_some) {
        char *s = xmalloc(cfg->server_name.val.len + 1);
        memcpy(s, cfg->server_name.val.ptr, cfg->server_name.val.len);
        s[cfg->server_name.val.len] = 0;
        SSL_set_tlsext_host_name(ssl, s);
        SSL_set1_host(ssl, s);
        free(s);
    } else {
        SSL_set_tlsext_host_name(ssl, hostnul);
        SSL_set1_host(ssl, hostnul);
    }
    SSL_set_fd(ssl, fd);

    if (SSL_connect(ssl) != 1) {
        int e = SSL_get_error(ssl, -1);
        if (pre_keylog) { keylog_buf_clear(pre_keylog); free(pre_keylog); }
        SSL_free(ssl); close(fd); SSL_CTX_free(ctx); free(hostnul);
        err->tag = TE_HANDSHAKE;
        err->val.internal = (uint64_t)e;
        return false;
    }

    free(hostnul);
    client_rep *r = xmalloc(sizeof(*r));
    r->ctx = ctx; r->ssl = ssl; r->fd = fd;
    if (pre_keylog) {
        r->keylog = *pre_keylog;
        free(pre_keylog);
        // Point SSL ex-data at the final stable address inside the rep.
        SSL_set_ex_data(ssl, keylog_ssl_ex_idx(), &r->keylog);
    } else {
        keylog_buf_init(&r->keylog);
    }
    *ret = exports_openssl_component_tls_client_new(
        (exports_openssl_component_tls_client_t *)r);
    return true;
}

bool exports_openssl_component_tls_method_client_write(
        exports_openssl_component_tls_borrow_client_t self,
        openssl_list_u8_t *data, uint32_t *ret,
        exports_openssl_component_tls_tls_error_t *err) {
    client_rep *r = (client_rep *)self;
    int n = SSL_write(r->ssl, data->ptr, (int)data->len);
    if (n <= 0) {
        int e = SSL_get_error(r->ssl, n);
        err->tag = (e == SSL_ERROR_ZERO_RETURN) ? TE_IO_CLOSED : TE_INTERNAL;
        err->val.internal = (uint64_t)e;
        return false;
    }
    *ret = (uint32_t)n;
    return true;
}

bool exports_openssl_component_tls_method_client_read(
        exports_openssl_component_tls_borrow_client_t self,
        uint32_t max_bytes, openssl_list_u8_t *ret,
        exports_openssl_component_tls_tls_error_t *err) {
    client_rep *r = (client_rep *)self;
    ret->ptr = xmalloc(max_bytes ? max_bytes : 1);
    int n = SSL_read(r->ssl, ret->ptr, (int)max_bytes);
    if (n < 0) {
        free(ret->ptr);
        int e = SSL_get_error(r->ssl, n);
        err->tag = TE_INTERNAL; err->val.internal = (uint64_t)e;
        return false;
    }
    ret->len = (size_t)n;
    return true;
}

bool exports_openssl_component_tls_method_client_has_pending(
        exports_openssl_component_tls_borrow_client_t self) {
    client_rep *r = (client_rep *)self;
    return SSL_has_pending(r->ssl) != 0;
}

bool exports_openssl_component_tls_method_client_socket_readable(
        exports_openssl_component_tls_borrow_client_t self) {
    client_rep *r = (client_rep *)self;
    int fd = SSL_get_fd(r->ssl);
    if (fd < 0) return false;
    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    /* timeout=5ms. With timeout=0 the trailer record (e.g. the HTTP
     * chunk-end sentinel arriving as a separate TLS record after the
     * body) hasn't usually landed in the kernel TCP buffer by the time
     * the drain loop checks — server packetizes it microseconds after
     * the body. 5ms is enough wall-clock for the trailer to arrive
     * without making keepalive-idle calls visibly slow. */
    int n = poll(&pfd, 1, 1);
    if (n <= 0) return false;
    return (pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0;
}

int32_t exports_openssl_component_tls_method_client_socket_fd(
        exports_openssl_component_tls_borrow_client_t self) {
    client_rep *r = (client_rep *)self;
    return SSL_get_fd(r->ssl);
}

bool exports_openssl_component_tls_method_client_write_early(
        exports_openssl_component_tls_borrow_client_t self,
        openssl_list_u8_t *data, uint32_t *ret,
        exports_openssl_component_tls_tls_error_t *err) {
    client_rep *r = (client_rep *)self;
    size_t w = 0;
    int rc = SSL_write_early_data(r->ssl, data->ptr, data->len, &w);
    if (rc <= 0) {
        err->tag = TE_INTERNAL;
        err->val.internal = SSL_get_error(r->ssl, rc);
        return false;
    }
    *ret = (uint32_t)w;
    return true;
}

bool exports_openssl_component_tls_method_client_early_data_accepted(
        exports_openssl_component_tls_borrow_client_t self) {
    client_rep *r = (client_rep *)self;
    return SSL_get_early_data_status(r->ssl) == SSL_EARLY_DATA_ACCEPTED;
}

void exports_openssl_component_tls_method_client_peer(
        exports_openssl_component_tls_borrow_client_t self,
        exports_openssl_component_tls_peer_info_t *ret) {
    client_rep *r = (client_rep *)self;
    fill_peer_info(r->ssl, ret);
}

bool exports_openssl_component_tls_method_client_session_ticket(
        exports_openssl_component_tls_borrow_client_t self,
        openssl_list_u8_t *ret) {
    client_rep *r = (client_rep *)self;
    SSL_SESSION *s = SSL_get1_session(r->ssl);
    if (!s) return false;
    unsigned char *buf = NULL;
    int n = i2d_SSL_SESSION(s, &buf);
    SSL_SESSION_free(s);
    if (n <= 0) { if (buf) OPENSSL_free(buf); return false; }
    list_u8_take(ret, buf, n);
    OPENSSL_free(buf);
    return true;
}

void exports_openssl_component_tls_method_client_drain_keylog(
        exports_openssl_component_tls_borrow_client_t self,
        openssl_list_string_t *ret) {
    client_rep *r = (client_rep *)self;
    keylog_buf_drain_to(&r->keylog, ret);
}

void exports_openssl_component_tls_static_client_close(
        exports_openssl_component_tls_own_client_t handle) {
    client_rep *r = (client_rep *)
        exports_openssl_component_tls_client_rep(handle);
    if (r->ssl) { SSL_shutdown(r->ssl); SSL_free(r->ssl); }
    if (r->fd >= 0) close(r->fd);
    if (r->ctx) SSL_CTX_free(r->ctx);
    r->ssl = NULL; r->ctx = NULL; r->fd = -1;
    exports_openssl_component_tls_client_drop_own(handle);
}

void exports_openssl_component_tls_client_destructor(
        exports_openssl_component_tls_client_t *rep) {
    client_rep *r = (client_rep *)rep;
    if (!r) return;
    if (r->ssl) { SSL_shutdown(r->ssl); SSL_free(r->ssl); }
    if (r->fd >= 0) close(r->fd);
    if (r->ctx) SSL_CTX_free(r->ctx);
    keylog_buf_clear(&r->keylog);
    free(r);
}

// --- server --------------------------------------------------------------

typedef struct server_listener_rep {
    SSL_CTX *ctx;
    int fd;
    unsigned char *alpn_wire;   /* owned; freed with rep; may be NULL */
    size_t alpn_wire_len;
    bool keylog_enabled;
} server_listener_rep;

typedef struct server_rep {
    SSL *ssl;
    int fd;
    keylog_buf keylog;
} server_rep;

// ALPN server-side selection callback. The wire-format server list is
// passed as the callback arg (stashed in the listener rep).
static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl;
    const unsigned char *server_list = arg;
    if (!server_list) return SSL_TLSEXT_ERR_NOACK;
    // server_list is wire-format: length-prefixed entries, double-NUL terminated
    // (we store the full wire-bytes plus a trailing 0 for termination).
    size_t slen = 0;
    while (server_list[slen]) slen += 1 + server_list[slen];
    int rc = SSL_select_next_proto((unsigned char **)out, outlen,
                                   server_list, (unsigned int)slen,
                                   in, inlen);
    return rc == OPENSSL_NPN_NEGOTIATED ? SSL_TLSEXT_ERR_OK
                                         : SSL_TLSEXT_ERR_NOACK;
}

// See client_connect: DTLS is not implemented. Reject cleanly.
bool exports_openssl_component_tls_static_server_listener_bind(
        openssl_string_t *host, uint16_t port,
        exports_openssl_component_tls_server_config_t *cfg,
        exports_openssl_component_tls_own_server_listener_t *ret,
        exports_openssl_component_tls_tls_error_t *err) {
    if (cfg->protocols.min == 2 || cfg->protocols.max == 2) {
        err->tag = TE_PROTOCOL;
        err->val.internal = 0;
        return false;
    }
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { err->tag = TE_BAD_CONFIG; return false; }
    apply_protocols(ctx, &cfg->protocols);
    apply_ciphers(ctx, &cfg->ciphers);
    apply_groups(ctx, &cfg->groups);

    int mode = cfg->verify == 0 ? SSL_VERIFY_NONE
             : cfg->verify == 1 ? (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
             : SSL_VERIFY_PEER;
    SSL_CTX_set_verify(ctx, mode, NULL);

    if (cfg->client_trust.is_some) {
        X509_STORE *s = (X509_STORE *)
            exports_openssl_component_x509_store_rep(cfg->client_trust.val);
        X509_STORE_up_ref(s);
        SSL_CTX_set_cert_store(ctx, s);
    }

    if (cfg->cert_chain.len >= 1) {
        SSL_CTX_use_certificate(ctx,
            (X509 *)exports_openssl_component_x509_certificate_rep(cfg->cert_chain.ptr[0]));
        for (size_t i = 1; i < cfg->cert_chain.len; i++) {
            SSL_CTX_add1_chain_cert(ctx,
                (X509 *)exports_openssl_component_x509_certificate_rep(cfg->cert_chain.ptr[i]));
        }
    }
    SSL_CTX_use_PrivateKey(ctx,
        (EVP_PKEY *)exports_openssl_component_pkey_pkey_rep(cfg->key));
    if (cfg->keylog) {
        SSL_CTX_set_keylog_callback(ctx, keylog_cb);
    }

    char *hostnul = xmalloc(host->len + 1);
    memcpy(hostnul, host->ptr, host->len);
    hostnul[host->len] = 0;
    int ioerr = 0;
    int fd = bind_tcp(hostnul, port, &ioerr);
    free(hostnul);
    if (fd < 0) {
        SSL_CTX_free(ctx);
        err->tag = TE_IO_CLOSED; err->val.internal = (uint64_t)ioerr;
        return false;
    }

    server_listener_rep *r = xmalloc(sizeof(*r));
    r->ctx = ctx; r->fd = fd;
    r->alpn_wire = NULL; r->alpn_wire_len = 0;
    r->keylog_enabled = cfg->keylog;

    // Server-side ALPN: store the offered wire-format in the rep and
    // wire it through a select callback (per-CTX arg).
    if (cfg->alpn.is_some) {
        size_t w = 0;
        r->alpn_wire = alpn_wire(&cfg->alpn, &w);
        if (r->alpn_wire) {
            // We need a nul terminator for our callback's length scan.
            unsigned char *nul = xmalloc(w + 1);
            memcpy(nul, r->alpn_wire, w);
            nul[w] = 0;
            free(r->alpn_wire);
            r->alpn_wire = nul;
            r->alpn_wire_len = w;
            SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, r->alpn_wire);
        }
    }

    *ret = exports_openssl_component_tls_server_listener_new(
        (exports_openssl_component_tls_server_listener_t *)r);
    return true;
}

bool exports_openssl_component_tls_method_server_listener_accept(
        exports_openssl_component_tls_borrow_server_listener_t self,
        exports_openssl_component_tls_own_server_t *ret,
        exports_openssl_component_tls_tls_error_t *err) {
    server_listener_rep *lr = (server_listener_rep *)self;
    int cfd = accept(lr->fd, NULL, NULL);
    if (cfd < 0) { err->tag = TE_IO_CLOSED; err->val.internal = (uint64_t)errno; return false; }
    SSL *ssl = SSL_new(lr->ctx);
    if (!ssl) { close(cfd); err->tag = TE_INTERNAL; return false; }
    SSL_set_fd(ssl, cfd);

    // If the listener had keylog enabled, attach a per-connection buffer
    // to the SSL before the handshake runs.
    keylog_buf *pre_keylog = NULL;
    if (lr->keylog_enabled) {
        pre_keylog = xmalloc(sizeof(*pre_keylog));
        keylog_buf_init(pre_keylog);
        SSL_set_ex_data(ssl, keylog_ssl_ex_idx(), pre_keylog);
    }

    if (SSL_accept(ssl) != 1) {
        int e = SSL_get_error(ssl, -1);
        if (pre_keylog) { keylog_buf_clear(pre_keylog); free(pre_keylog); }
        SSL_free(ssl); close(cfd);
        err->tag = TE_HANDSHAKE; err->val.internal = (uint64_t)e;
        return false;
    }
    server_rep *r = xmalloc(sizeof(*r));
    r->ssl = ssl; r->fd = cfd;
    if (pre_keylog) {
        r->keylog = *pre_keylog;
        free(pre_keylog);
        SSL_set_ex_data(ssl, keylog_ssl_ex_idx(), &r->keylog);
    } else {
        keylog_buf_init(&r->keylog);
    }
    *ret = exports_openssl_component_tls_server_new(
        (exports_openssl_component_tls_server_t *)r);
    return true;
}

uint16_t exports_openssl_component_tls_method_server_listener_local_port(
        exports_openssl_component_tls_borrow_server_listener_t self) {
    server_listener_rep *r = (server_listener_rep *)self;
    struct sockaddr_storage ss; socklen_t sl = sizeof(ss);
    if (getsockname(r->fd, (struct sockaddr *)&ss, &sl) < 0) return 0;
    if (ss.ss_family == AF_INET)
        return ntohs(((struct sockaddr_in *)&ss)->sin_port);
    if (ss.ss_family == AF_INET6)
        return ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    return 0;
}

void exports_openssl_component_tls_static_server_listener_close(
        exports_openssl_component_tls_own_server_listener_t handle) {
    server_listener_rep *r = (server_listener_rep *)
        exports_openssl_component_tls_server_listener_rep(handle);
    if (r->fd >= 0) close(r->fd);
    if (r->ctx) SSL_CTX_free(r->ctx);
    if (r->alpn_wire) { free(r->alpn_wire); r->alpn_wire = NULL; }
    r->fd = -1; r->ctx = NULL;
    exports_openssl_component_tls_server_listener_drop_own(handle);
}

void exports_openssl_component_tls_server_listener_destructor(
        exports_openssl_component_tls_server_listener_t *rep) {
    server_listener_rep *r = (server_listener_rep *)rep;
    if (!r) return;
    if (r->fd >= 0) close(r->fd);
    if (r->ctx) SSL_CTX_free(r->ctx);
    if (r->alpn_wire) free(r->alpn_wire);
    free(r);
}

bool exports_openssl_component_tls_method_server_write(
        exports_openssl_component_tls_borrow_server_t self,
        openssl_list_u8_t *data, uint32_t *ret,
        exports_openssl_component_tls_tls_error_t *err) {
    server_rep *r = (server_rep *)self;
    int n = SSL_write(r->ssl, data->ptr, (int)data->len);
    if (n <= 0) {
        int e = SSL_get_error(r->ssl, n);
        err->tag = (e == SSL_ERROR_ZERO_RETURN) ? TE_IO_CLOSED : TE_INTERNAL;
        err->val.internal = (uint64_t)e;
        return false;
    }
    *ret = (uint32_t)n;
    return true;
}

bool exports_openssl_component_tls_method_server_read(
        exports_openssl_component_tls_borrow_server_t self,
        uint32_t max_bytes, openssl_list_u8_t *ret,
        exports_openssl_component_tls_tls_error_t *err) {
    server_rep *r = (server_rep *)self;
    ret->ptr = xmalloc(max_bytes ? max_bytes : 1);
    int n = SSL_read(r->ssl, ret->ptr, (int)max_bytes);
    if (n < 0) {
        free(ret->ptr);
        int e = SSL_get_error(r->ssl, n);
        err->tag = TE_INTERNAL; err->val.internal = (uint64_t)e;
        return false;
    }
    ret->len = (size_t)n;
    return true;
}

bool exports_openssl_component_tls_method_server_has_pending(
        exports_openssl_component_tls_borrow_server_t self) {
    server_rep *r = (server_rep *)self;
    return SSL_has_pending(r->ssl) != 0;
}

bool exports_openssl_component_tls_method_server_socket_readable(
        exports_openssl_component_tls_borrow_server_t self) {
    server_rep *r = (server_rep *)self;
    int fd = SSL_get_fd(r->ssl);
    if (fd < 0) return false;
    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    int n = poll(&pfd, 1, 1);
    if (n <= 0) return false;
    return (pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0;
}

int32_t exports_openssl_component_tls_method_server_socket_fd(
        exports_openssl_component_tls_borrow_server_t self) {
    server_rep *r = (server_rep *)self;
    return SSL_get_fd(r->ssl);
}

void exports_openssl_component_tls_method_server_peer(
        exports_openssl_component_tls_borrow_server_t self,
        exports_openssl_component_tls_peer_info_t *ret) {
    server_rep *r = (server_rep *)self;
    fill_peer_info(r->ssl, ret);
}

void exports_openssl_component_tls_method_server_drain_keylog(
        exports_openssl_component_tls_borrow_server_t self,
        openssl_list_string_t *ret) {
    server_rep *r = (server_rep *)self;
    keylog_buf_drain_to(&r->keylog, ret);
}

void exports_openssl_component_tls_static_server_close(
        exports_openssl_component_tls_own_server_t handle) {
    server_rep *r = (server_rep *)
        exports_openssl_component_tls_server_rep(handle);
    if (r->ssl) { SSL_shutdown(r->ssl); SSL_free(r->ssl); }
    if (r->fd >= 0) close(r->fd);
    r->ssl = NULL; r->fd = -1;
    exports_openssl_component_tls_server_drop_own(handle);
}

void exports_openssl_component_tls_server_destructor(
        exports_openssl_component_tls_server_t *rep) {
    server_rep *r = (server_rep *)rep;
    if (!r) return;
    if (r->ssl) { SSL_shutdown(r->ssl); SSL_free(r->ssl); }
    if (r->fd >= 0) close(r->fd);
    keylog_buf_clear(&r->keylog);
    free(r);
}

// --- mem-bio-client ------------------------------------------------------
// Memory-BIO TLS client. The SSL object is wired to two BIO_s_mem()
// instances: `in_bio` is OpenSSL's read-side (caller pumps ciphertext
// FROM the network into it via bio-write), and `out_bio` is the
// write-side (caller drains ciphertext to send TO the network via
// bio-read). The component never touches a socket — anyio/httpx own
// the transport and the event loop.

typedef struct mem_bio_client_rep {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *in_bio;   /* SSL reads here (we write incoming ciphertext into it) */
    BIO *out_bio;  /* SSL writes here (we read outgoing ciphertext from it) */
    int handshake_done;
    keylog_buf keylog;     /* non-empty iff cfg->keylog == true */
} mem_bio_client_rep;

bool exports_openssl_component_tls_static_mem_bio_client_new(
        exports_openssl_component_tls_client_config_t *cfg,
        exports_openssl_component_tls_own_mem_bio_client_t *ret,
        exports_openssl_component_tls_tls_error_t *err) {
    if (cfg->protocols.min == 2 || cfg->protocols.max == 2) {
        err->tag = TE_PROTOCOL; err->val.internal = 0; return false;
    }
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { err->tag = TE_BAD_CONFIG; return false; }
    apply_protocols(ctx, &cfg->protocols);
    apply_ciphers(ctx, &cfg->ciphers);
    apply_groups(ctx, &cfg->groups);
    SSL_CTX_set_verify(ctx,
        cfg->verify == 0 ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, NULL);
    if (cfg->trust.is_some) {
        X509_STORE *s = (X509_STORE *)
            exports_openssl_component_x509_store_rep(cfg->trust.val);
        X509_STORE_up_ref(s);
        SSL_CTX_set_cert_store(ctx, s);
    }
    if (cfg->client_cert.is_some) {
        SSL_CTX_use_certificate(ctx,
            (X509 *)exports_openssl_component_x509_certificate_rep(cfg->client_cert.val));
    }
    if (cfg->client_key.is_some) {
        SSL_CTX_use_PrivateKey(ctx,
            (EVP_PKEY *)exports_openssl_component_pkey_pkey_rep(cfg->client_key.val));
    }
    if (cfg->keylog) {
        SSL_CTX_set_keylog_callback(ctx, keylog_cb);
    }
    size_t alpn_len = 0;
    unsigned char *alpn = alpn_wire(&cfg->alpn, &alpn_len);
    if (alpn) {
        SSL_CTX_set_alpn_protos(ctx, alpn, (unsigned int)alpn_len);
        free(alpn);
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); err->tag = TE_BAD_CONFIG; return false; }

    keylog_buf *pre_keylog = NULL;
    if (cfg->keylog) {
        pre_keylog = xmalloc(sizeof(*pre_keylog));
        keylog_buf_init(pre_keylog);
        SSL_set_ex_data(ssl, keylog_ssl_ex_idx(), pre_keylog);
    }
    if (cfg->server_name.is_some) {
        char *s = xmalloc(cfg->server_name.val.len + 1);
        memcpy(s, cfg->server_name.val.ptr, cfg->server_name.val.len);
        s[cfg->server_name.val.len] = 0;
        SSL_set_tlsext_host_name(ssl, s);
        SSL_set1_host(ssl, s);
        free(s);
    }

    BIO *in_bio = BIO_new(BIO_s_mem());
    BIO *out_bio = BIO_new(BIO_s_mem());
    if (!in_bio || !out_bio) {
        if (in_bio) BIO_free(in_bio);
        if (out_bio) BIO_free(out_bio);
        if (pre_keylog) { keylog_buf_clear(pre_keylog); free(pre_keylog); }
        SSL_free(ssl); SSL_CTX_free(ctx);
        err->tag = TE_BAD_CONFIG; return false;
    }
    SSL_set_bio(ssl, in_bio, out_bio);
    SSL_set_connect_state(ssl);

    mem_bio_client_rep *r = xmalloc(sizeof(*r));
    r->ctx = ctx;
    r->ssl = ssl;
    r->in_bio = in_bio;
    r->out_bio = out_bio;
    r->handshake_done = 0;
    if (pre_keylog) {
        r->keylog = *pre_keylog;
        free(pre_keylog);
        SSL_set_ex_data(ssl, keylog_ssl_ex_idx(), &r->keylog);
    } else {
        keylog_buf_init(&r->keylog);
    }
    *ret = exports_openssl_component_tls_mem_bio_client_new(
        (exports_openssl_component_tls_mem_bio_client_t *)r);
    return true;
}

bool exports_openssl_component_tls_method_mem_bio_client_do_handshake(
        exports_openssl_component_tls_borrow_mem_bio_client_t self,
        exports_openssl_component_tls_tls_error_t *err) {
    mem_bio_client_rep *r = (mem_bio_client_rep *)self;
    int rc = SSL_do_handshake(r->ssl);
    if (rc == 1) {
        r->handshake_done = 1;
        return true;
    }
    int e = SSL_get_error(r->ssl, rc);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
        err->tag = TE_WOULD_BLOCK; err->val.internal = (uint64_t)e; return false;
    }
    err->tag = TE_HANDSHAKE; err->val.internal = (uint64_t)e;
    return false;
}

bool exports_openssl_component_tls_method_mem_bio_client_handshake_done(
        exports_openssl_component_tls_borrow_mem_bio_client_t self) {
    mem_bio_client_rep *r = (mem_bio_client_rep *)self;
    return r->handshake_done != 0;
}

uint32_t exports_openssl_component_tls_method_mem_bio_client_bio_write(
        exports_openssl_component_tls_borrow_mem_bio_client_t self,
        openssl_list_u8_t *data) {
    mem_bio_client_rep *r = (mem_bio_client_rep *)self;
    if (!data->len) return 0;
    int n = BIO_write(r->in_bio, data->ptr, (int)data->len);
    return n < 0 ? 0 : (uint32_t)n;
}

void exports_openssl_component_tls_method_mem_bio_client_bio_read(
        exports_openssl_component_tls_borrow_mem_bio_client_t self,
        uint32_t max, openssl_list_u8_t *ret) {
    mem_bio_client_rep *r = (mem_bio_client_rep *)self;
    size_t pending = BIO_ctrl_pending(r->out_bio);
    size_t take = pending < (size_t)max ? pending : (size_t)max;
    if (!take) { ret->ptr = NULL; ret->len = 0; return; }
    ret->ptr = xmalloc(take);
    int n = BIO_read(r->out_bio, ret->ptr, (int)take);
    if (n < 0) n = 0;
    ret->len = (size_t)n;
}

uint32_t exports_openssl_component_tls_method_mem_bio_client_bio_pending(
        exports_openssl_component_tls_borrow_mem_bio_client_t self) {
    mem_bio_client_rep *r = (mem_bio_client_rep *)self;
    return (uint32_t)BIO_ctrl_pending(r->out_bio);
}

bool exports_openssl_component_tls_method_mem_bio_client_read(
        exports_openssl_component_tls_borrow_mem_bio_client_t self,
        uint32_t max_bytes, openssl_list_u8_t *ret,
        exports_openssl_component_tls_tls_error_t *err) {
    mem_bio_client_rep *r = (mem_bio_client_rep *)self;
    ret->ptr = xmalloc(max_bytes ? max_bytes : 1);
    int n = SSL_read(r->ssl, ret->ptr, (int)max_bytes);
    if (n < 0) {
        int e = SSL_get_error(r->ssl, n);
        free(ret->ptr); ret->ptr = NULL; ret->len = 0;
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            err->tag = TE_WOULD_BLOCK; err->val.internal = (uint64_t)e; return false;
        }
        err->tag = (e == SSL_ERROR_ZERO_RETURN) ? TE_IO_CLOSED : TE_INTERNAL;
        err->val.internal = (uint64_t)e;
        return false;
    }
    ret->len = (size_t)n;
    return true;
}

bool exports_openssl_component_tls_method_mem_bio_client_write(
        exports_openssl_component_tls_borrow_mem_bio_client_t self,
        openssl_list_u8_t *data, uint32_t *written,
        exports_openssl_component_tls_tls_error_t *err) {
    mem_bio_client_rep *r = (mem_bio_client_rep *)self;
    if (!data->len) { *written = 0; return true; }
    int n = SSL_write(r->ssl, data->ptr, (int)data->len);
    if (n <= 0) {
        int e = SSL_get_error(r->ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            err->tag = TE_WOULD_BLOCK; err->val.internal = (uint64_t)e; return false;
        }
        err->tag = TE_INTERNAL; err->val.internal = (uint64_t)e;
        return false;
    }
    *written = (uint32_t)n;
    return true;
}

bool exports_openssl_component_tls_method_mem_bio_client_peer_cert_der(
        exports_openssl_component_tls_borrow_mem_bio_client_t self,
        openssl_list_u8_t *ret) {
    mem_bio_client_rep *r = (mem_bio_client_rep *)self;
    X509 *cert = SSL_get1_peer_certificate(r->ssl);
    if (!cert) return false;
    unsigned char *buf = NULL;
    int n = i2d_X509(cert, &buf);
    X509_free(cert);
    if (n <= 0) { if (buf) OPENSSL_free(buf); return false; }
    list_u8_take(ret, buf, n);
    OPENSSL_free(buf);
    return true;
}

void exports_openssl_component_tls_method_mem_bio_client_version(
        exports_openssl_component_tls_borrow_mem_bio_client_t self,
        openssl_string_t *ret) {
    mem_bio_client_rep *r = (mem_bio_client_rep *)self;
    const char *v = SSL_get_version(r->ssl);
    if (!v) v = "";
    string_take(ret, v, strlen(v));
}

bool exports_openssl_component_tls_method_mem_bio_client_selected_alpn_protocol(
        exports_openssl_component_tls_borrow_mem_bio_client_t self,
        openssl_string_t *ret) {
    mem_bio_client_rep *r = (mem_bio_client_rep *)self;
    const unsigned char *alpn = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(r->ssl, &alpn, &alpn_len);
    if (!alpn || !alpn_len) return false;
    string_take(ret, (const char *)alpn, alpn_len);
    return true;
}

void exports_openssl_component_tls_method_mem_bio_client_peer(
        exports_openssl_component_tls_borrow_mem_bio_client_t self,
        exports_openssl_component_tls_peer_info_t *ret) {
    mem_bio_client_rep *r = (mem_bio_client_rep *)self;
    fill_peer_info(r->ssl, ret);
}

bool exports_openssl_component_tls_method_mem_bio_client_shutdown(
        exports_openssl_component_tls_borrow_mem_bio_client_t self,
        exports_openssl_component_tls_tls_error_t *err) {
    mem_bio_client_rep *r = (mem_bio_client_rep *)self;
    int rc = SSL_shutdown(r->ssl);
    if (rc < 0) {
        int e = SSL_get_error(r->ssl, rc);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            err->tag = TE_WOULD_BLOCK; err->val.internal = (uint64_t)e; return false;
        }
        err->tag = TE_INTERNAL; err->val.internal = (uint64_t)e;
        return false;
    }
    return true;
}

void exports_openssl_component_tls_static_mem_bio_client_close(
        exports_openssl_component_tls_own_mem_bio_client_t handle) {
    mem_bio_client_rep *r = (mem_bio_client_rep *)
        exports_openssl_component_tls_mem_bio_client_rep(handle);
    if (r->ssl) { SSL_free(r->ssl); /* frees the attached BIOs */ }
    if (r->ctx) SSL_CTX_free(r->ctx);
    r->ssl = NULL; r->ctx = NULL; r->in_bio = NULL; r->out_bio = NULL;
    exports_openssl_component_tls_mem_bio_client_drop_own(handle);
}

void exports_openssl_component_tls_mem_bio_client_destructor(
        exports_openssl_component_tls_mem_bio_client_t *rep) {
    mem_bio_client_rep *r = (mem_bio_client_rep *)rep;
    if (!r) return;
    if (r->ssl) SSL_free(r->ssl);  /* frees BIOs */
    if (r->ctx) SSL_CTX_free(r->ctx);
    keylog_buf_clear(&r->keylog);
    free(r);
}
