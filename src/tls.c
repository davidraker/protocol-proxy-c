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

/* One TLS session. An SSL object must never be used by two threads at once, and a persistent connection has a reader
 * thread in SSL_read while another thread calls SSL_write (the first frame after the handshake, while the server's
 * NewSessionTicket records are still arriving, is the usual collision), so every call into OpenSSL on the session
 * takes its lock. The lock is never held while waiting on the socket, so a reader blocked in poll() does not stop a
 * writer. */
typedef struct {
    SSL *ssl;
    int fd;
    pthread_mutex_t lock;
} tls_session;

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
    /* A peer that closes the socket without a close_notify (the Python manager does on stop) is an EOF, not an error. */
    SSL_CTX_set_options(t->ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
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

/* Map the SSL_get_error code of a failed non-blocking operation to what the caller must do: 1 wait for the socket
 * (events set), 0 end of stream (eof set), or a negative error. errno and the OpenSSL error queue are per thread,
 * so they are read right after the call, before any other OpenSSL call on this thread. */
static int classify(int e, short *events, bool *eof) {
    if (eof) *eof = false;
    switch (e) {
    case SSL_ERROR_WANT_READ: *events = POLLIN; return 1;
    case SSL_ERROR_WANT_WRITE: *events = POLLOUT; return 1;
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

static int remaining(double deadline, int timeout_ms) {
    if (timeout_ms < 0) return -1;
    double left = (deadline - ppc_monotonic()) * 1000.0;
    return left <= 0 ? 0 : (int)left + 1;
}

int ppc_tls_handshake(struct ppc_tls_ctx *t, int fd, bool server, const char *server_name, ppc_wait_fn wait,
                      void *arg, int timeout_ms, void **ssl_out) {
    if (t == NULL || ssl_out == NULL) return PPC_ERR_INVALID;
    tls_session *s = calloc(1, sizeof *s);
    if (s == NULL) return PPC_ERR_NOMEM;
    s->ssl = SSL_new(t->ctx);
    if (s->ssl == NULL) { free(s); return PPC_ERR_NOMEM; }
    s->fd = fd;
    pthread_mutex_init(&s->lock, NULL);
    SSL_set_fd(s->ssl, fd);
    if (server) SSL_set_accept_state(s->ssl);
    else {
        SSL_set_connect_state(s->ssl);
        if (server_name) SSL_set_tlsext_host_name(s->ssl, server_name);
    }
    double deadline = timeout_ms < 0 ? 0 : ppc_monotonic() + timeout_ms / 1000.0;
    for (;;) {
        pthread_mutex_lock(&s->lock);
        int r = SSL_do_handshake(s->ssl);
        int e = r == 1 ? SSL_ERROR_NONE : SSL_get_error(s->ssl, r);
        pthread_mutex_unlock(&s->lock);
        if (r == 1) break;
        short events = POLLIN;
        int c = classify(e, &events, NULL);
        int left = remaining(deadline, timeout_ms);
        if (c < 0 || (timeout_ms >= 0 && left <= 0)) { ppc_tls_free(s); return c < 0 ? PPC_ERR_TLS : PPC_ERR_TIMEOUT; }
        int w = wait(arg, fd, events, left);
        if (w == 0) { ppc_tls_free(s); return PPC_ERR_TIMEOUT; }
        if (w < 0) { ppc_tls_free(s); return w == PPC_ERR_STOPPED ? w : PPC_ERR_TLS; }
    }
    if (!server && server_name) {
        char cn[256];
        if (ppc_tls_peer_common_name(s, cn, sizeof cn) != PPC_OK || strcmp(cn, server_name) != 0) {
            ppc_tls_free(s);
            return PPC_ERR_TLS;
        }
    }
    *ssl_out = s;
    return PPC_OK;
}

ssize_t ppc_tls_read(void *vssl, uint8_t *buf, size_t len, ppc_wait_fn wait, void *arg, int timeout_ms) {
    tls_session *s = vssl;
    double deadline = timeout_ms < 0 ? 0 : ppc_monotonic() + timeout_ms / 1000.0;
    for (;;) {
        size_t n = 0;
        pthread_mutex_lock(&s->lock);
        int r = SSL_read_ex(s->ssl, buf, len, &n);
        int e = r == 1 ? SSL_ERROR_NONE : SSL_get_error(s->ssl, r);
        bool eof = false;
        short events = POLLIN;
        int c = r == 1 ? 0 : classify(e, &events, &eof);
        pthread_mutex_unlock(&s->lock);
        if (r == 1) return (ssize_t)n;
        if (eof) return 0;
        if (c < 0) return c;
        int left = remaining(deadline, timeout_ms);
        if (timeout_ms >= 0 && left <= 0) return PPC_ERR_TIMEOUT;
        int w = wait(arg, s->fd, events, left);
        if (w == 0) return PPC_ERR_TIMEOUT;
        if (w < 0) return w;
    }
}

int ppc_tls_write(void *vssl, const uint8_t *buf, size_t len, ppc_wait_fn wait, void *arg, int timeout_ms) {
    tls_session *s = vssl;
    double deadline = timeout_ms < 0 ? 0 : ppc_monotonic() + timeout_ms / 1000.0;
    while (len) {
        size_t n = 0;
        pthread_mutex_lock(&s->lock);
        int r = SSL_write_ex(s->ssl, buf, len, &n);
        int e = r == 1 ? SSL_ERROR_NONE : SSL_get_error(s->ssl, r);
        short events = POLLOUT;
        int c = r == 1 ? 0 : classify(e, &events, NULL);
        pthread_mutex_unlock(&s->lock);
        if (r == 1) { buf += n; len -= n; continue; }
        if (c < 0) return c;
        int left = remaining(deadline, timeout_ms);
        if (timeout_ms >= 0 && left <= 0) return PPC_ERR_TIMEOUT;
        int w = wait(arg, s->fd, events, left);
        if (w == 0) return PPC_ERR_TIMEOUT;
        if (w < 0) return w;
    }
    return PPC_OK;
}

int ppc_tls_peer_common_name(void *vssl, char *out, size_t out_len) {
    tls_session *s = vssl;
    pthread_mutex_lock(&s->lock);
    X509 *cert = SSL_get1_peer_certificate(s->ssl);
    pthread_mutex_unlock(&s->lock);
    if (cert == NULL) return PPC_ERR_TLS;
    int n = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, out, (int)out_len);
    X509_free(cert);
    return n > 0 ? PPC_OK : PPC_ERR_TLS;
}

void ppc_tls_free(void *vssl) {
    if (vssl == NULL) return;
    tls_session *s = vssl;
    pthread_mutex_lock(&s->lock);
    SSL_shutdown(s->ssl);      /* one non-blocking attempt at a close_notify; the socket is closed regardless */
    SSL_free(s->ssl);
    pthread_mutex_unlock(&s->lock);
    pthread_mutex_destroy(&s->lock);
    ERR_clear_error();
    free(s);
}
