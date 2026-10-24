/* TLS 1.3 between a proxy and its manager (section 5, "TLS"), with OpenSSL over non-blocking sockets. Both ends
 * present a certificate issued by the manager's CA and require the other's to chain to it; hostnames are not
 * checked, the certificate's common name carries the peer's id and the connector compares it. */
#include "internal.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <poll.h>
#include <stdio.h>

struct ppc_tls_ctx {
    SSL_CTX *ctx;
};

static void openssl_error(char *err, size_t err_len, const char *what) {
    if (err == NULL || err_len == 0) return;
    char buf[256] = "";
    unsigned long code = ERR_get_error();
    if (code) ERR_error_string_n(code, buf, sizeof buf);
    snprintf(err, err_len, "%s: %s", what, buf[0] ? buf : "unknown OpenSSL error");
    ERR_clear_error();
}

int ppc_tls_material_parse(const char *line, size_t len, ppc_tls_material **out) {
    if (line == NULL || out == NULL) return PPC_ERR_INVALID;
    char err[128];
    ppc_json *v = ppc_json_parse(line, len, err, sizeof err);
    if (v == NULL) return PPC_ERR_INVALID;
    const char *ca = ppc_json_get_string(v, "ca", NULL), *cert = ppc_json_get_string(v, "cert", NULL),
               *key = ppc_json_get_string(v, "key", NULL);
    if (ca == NULL || cert == NULL || key == NULL) { ppc_json_free(v); return PPC_ERR_INVALID; }
    ppc_tls_material *m = calloc(1, sizeof *m);
    if (m == NULL) { ppc_json_free(v); return PPC_ERR_NOMEM; }
    m->ca = ppc_strdup(ca);
    m->cert = ppc_strdup(cert);
    m->key = ppc_strdup(key);
    ppc_json_free(v);
    if (m->ca == NULL || m->cert == NULL || m->key == NULL) { ppc_tls_material_free(m); return PPC_ERR_NOMEM; }
    *out = m;
    return PPC_OK;
}

void ppc_tls_material_free(ppc_tls_material *m) {
    if (m == NULL) return;
    free(m->ca);
    free(m->cert);
    if (m->key) { memset(m->key, 0, strlen(m->key)); free(m->key); }
    free(m);
}

struct ppc_tls_ctx *ppc_tls_ctx_new(const ppc_tls_material *m, bool server, char *err, size_t err_len) {
    if (m == NULL) return NULL;
    struct ppc_tls_ctx *t = calloc(1, sizeof *t);
    if (t == NULL) return NULL;
    t->ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (t->ctx == NULL) { openssl_error(err, err_len, "SSL_CTX_new"); free(t); return NULL; }
    SSL_CTX_set_min_proto_version(t->ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(t->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_mode(t->ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    /* CA certificates (one or more PEM blocks). */
    BIO *bio = BIO_new_mem_buf(m->ca, -1);
    X509_STORE *store = SSL_CTX_get_cert_store(t->ctx);
    int added = 0;
    for (;;) {
        X509 *x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (x == NULL) break;
        X509_STORE_add_cert(store, x);
        X509_free(x);
        added++;
    }
    BIO_free(bio);
    ERR_clear_error();
    if (added == 0) { snprintf(err ? err : (char[1]){0}, err ? err_len : 1, "no CA certificate in TLS material"); ppc_tls_ctx_free(t); return NULL; }
    /* Our certificate and key. */
    bio = BIO_new_mem_buf(m->cert, -1);
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (cert == NULL || SSL_CTX_use_certificate(t->ctx, cert) != 1) {
        openssl_error(err, err_len, "certificate"); if (cert) X509_free(cert); ppc_tls_ctx_free(t); return NULL;
    }
    X509_free(cert);
    bio = BIO_new_mem_buf(m->key, -1);
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (key == NULL || SSL_CTX_use_PrivateKey(t->ctx, key) != 1 || SSL_CTX_check_private_key(t->ctx) != 1) {
        openssl_error(err, err_len, "private key"); if (key) EVP_PKEY_free(key); ppc_tls_ctx_free(t); return NULL;
    }
    EVP_PKEY_free(key);
    return t;
}

void ppc_tls_ctx_free(struct ppc_tls_ctx *t) {
    if (t == NULL) return;
    if (t->ctx) SSL_CTX_free(t->ctx);
    free(t);
}

/* Run one non-blocking SSL operation to completion, waiting on the socket between attempts. op returns 1 on
 * success; on failure want tells what it needs. */
static int drive(SSL *ssl, int fd, int result, ppc_wait_fn wait, void *arg, int timeout_ms, bool *eof) {
    int e = SSL_get_error(ssl, result);
    if (eof) *eof = false;
    switch (e) {
    case SSL_ERROR_WANT_READ: return wait(arg, fd, POLLIN, timeout_ms);
    case SSL_ERROR_WANT_WRITE: return wait(arg, fd, POLLOUT, timeout_ms);
    case SSL_ERROR_ZERO_RETURN: if (eof) *eof = true; return PPC_ERR_CONNECTION;
    case SSL_ERROR_SYSCALL:
        if (eof && (errno == 0 || ERR_peek_error() == 0)) *eof = true;
        ERR_clear_error();
        return PPC_ERR_CONNECTION;
    default:
        ERR_clear_error();
        return PPC_ERR_TLS;
    }
}

int ppc_tls_handshake(struct ppc_tls_ctx *t, int fd, bool server, const char *server_name, ppc_wait_fn wait,
                      void *arg, int timeout_ms, void **ssl_out) {
    if (t == NULL || ssl_out == NULL) return PPC_ERR_INVALID;
    SSL *ssl = SSL_new(t->ctx);
    if (ssl == NULL) return PPC_ERR_NOMEM;
    SSL_set_fd(ssl, fd);
    if (server) SSL_set_accept_state(ssl);
    else {
        SSL_set_connect_state(ssl);
        if (server_name) SSL_set_tlsext_host_name(ssl, server_name);
    }
    double deadline = timeout_ms < 0 ? 0 : ppc_monotonic() + timeout_ms / 1000.0;
    for (;;) {
        int r = SSL_do_handshake(ssl);
        if (r == 1) break;
        int remaining = timeout_ms < 0 ? -1 : (int)((deadline - ppc_monotonic()) * 1000);
        if (timeout_ms >= 0 && remaining <= 0) { SSL_free(ssl); return PPC_ERR_TIMEOUT; }
        int w = drive(ssl, fd, r, wait, arg, remaining, NULL);
        if (w == 0) { SSL_free(ssl); return PPC_ERR_TIMEOUT; }
        if (w < 0) { SSL_free(ssl); return w == PPC_ERR_STOPPED ? w : PPC_ERR_TLS; }
    }
    if (!server && server_name) {
        char cn[256];
        if (ppc_tls_peer_common_name(ssl, cn, sizeof cn) != PPC_OK || strcmp(cn, server_name) != 0) {
            SSL_free(ssl);
            return PPC_ERR_TLS;
        }
    }
    *ssl_out = ssl;
    return PPC_OK;
}

ssize_t ppc_tls_read(void *vssl, uint8_t *buf, size_t len, ppc_wait_fn wait, void *arg, int timeout_ms) {
    SSL *ssl = vssl;
    int fd = SSL_get_fd(ssl);
    double deadline = timeout_ms < 0 ? 0 : ppc_monotonic() + timeout_ms / 1000.0;
    for (;;) {
        size_t n = 0;
        int r = SSL_read_ex(ssl, buf, len, &n);
        if (r == 1) return (ssize_t)n;
        bool eof;
        int remaining = timeout_ms < 0 ? -1 : (int)((deadline - ppc_monotonic()) * 1000);
        if (timeout_ms >= 0 && remaining <= 0) return PPC_ERR_TIMEOUT;
        int w = drive(ssl, fd, r, wait, arg, remaining, &eof);
        if (eof) return 0;
        if (w == 0) return PPC_ERR_TIMEOUT;
        if (w < 0) return w;
    }
}

int ppc_tls_write(void *vssl, const uint8_t *buf, size_t len, ppc_wait_fn wait, void *arg, int timeout_ms) {
    SSL *ssl = vssl;
    int fd = SSL_get_fd(ssl);
    double deadline = timeout_ms < 0 ? 0 : ppc_monotonic() + timeout_ms / 1000.0;
    while (len) {
        size_t n = 0;
        int r = SSL_write_ex(ssl, buf, len, &n);
        if (r == 1) { buf += n; len -= n; continue; }
        int remaining = timeout_ms < 0 ? -1 : (int)((deadline - ppc_monotonic()) * 1000);
        if (timeout_ms >= 0 && remaining <= 0) return PPC_ERR_TIMEOUT;
        int w = drive(ssl, fd, r, wait, arg, remaining, NULL);
        if (w == 0) return PPC_ERR_TIMEOUT;
        if (w < 0) return w;
    }
    return PPC_OK;
}

int ppc_tls_peer_common_name(void *vssl, char *out, size_t out_len) {
    X509 *cert = SSL_get1_peer_certificate((SSL *)vssl);
    if (cert == NULL) return PPC_ERR_TLS;
    int n = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, out, (int)out_len);
    X509_free(cert);
    return n > 0 ? PPC_OK : PPC_ERR_TLS;
}

void ppc_tls_free(void *vssl) {
    if (vssl == NULL) return;
    SSL *ssl = vssl;
    SSL_shutdown(ssl);      /* one non-blocking attempt at a close_notify; the socket is closed regardless */
    SSL_free(ssl);
    ERR_clear_error();
}
