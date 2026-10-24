/* Internal helpers shared by the library's translation units. */
#ifndef PPC_INTERNAL_H
#define PPC_INTERNAL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ppc/ppc.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#define PPC_LOGGER "protocol_proxy_c"
#define LOG_DEBUG(...) PPC_LOG_AT(PPC_LOG_DEBUG, PPC_LOGGER, __VA_ARGS__)
#define LOG_INFO(...) PPC_LOG_AT(PPC_LOG_INFO, PPC_LOGGER, __VA_ARGS__)
#define LOG_WARNING(...) PPC_LOG_AT(PPC_LOG_WARNING, PPC_LOGGER, __VA_ARGS__)
#define LOG_ERROR(...) PPC_LOG_AT(PPC_LOG_ERROR, PPC_LOGGER, __VA_ARGS__)

static inline double ppc_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static inline double ppc_monotonic(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static inline char *ppc_strdup(const char *s) {
    if (s == NULL) return NULL;
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    if (d) memcpy(d, s, n);
    return d;
}

/* Hex helpers (lower-case output). */
void ppc_hex_encode(const uint8_t *in, size_t len, char *out);
int ppc_hex_decode(const char *in, size_t in_len, uint8_t *out, size_t out_len);

/* Growable byte buffer. */
typedef struct {
    uint8_t *data;
    size_t len, cap;
} ppc_buf;
int ppc_buf_append(ppc_buf *b, const void *data, size_t len);
int ppc_buf_reserve(ppc_buf *b, size_t extra);
void ppc_buf_free(ppc_buf *b);

/* ISO 8601 (UTC, microseconds, +00:00) of a time() value; out holds at least 40 bytes. */
void ppc_iso8601(double when, char *out, size_t out_len);

/* Waits for fd readiness; returns 1 ready, 0 timeout, a negative code (PPC_ERR_STOPPED) when interrupted. */
typedef int (*ppc_wait_fn)(void *arg, int fd, short events, int timeout_ms);

/* TLS (tls.c) over non-blocking sockets. */
struct ppc_tls_ctx;
struct ppc_tls_ctx *ppc_tls_ctx_new(const ppc_tls_material *m, bool server, char *err, size_t err_len);
void ppc_tls_ctx_free(struct ppc_tls_ctx *ctx);
/* Handshake on a connected non-blocking fd; server_name is the SNI and expected common name for a client (NULL to
 * skip). *ssl_out receives the session. */
int ppc_tls_handshake(struct ppc_tls_ctx *ctx, int fd, bool server, const char *server_name, ppc_wait_fn wait,
                      void *arg, int timeout_ms, void **ssl_out);
/* >0 bytes, 0 EOF, negative code. */
ssize_t ppc_tls_read(void *ssl, uint8_t *buf, size_t len, ppc_wait_fn wait, void *arg, int timeout_ms);
int ppc_tls_write(void *ssl, const uint8_t *buf, size_t len, ppc_wait_fn wait, void *arg, int timeout_ms);
/* The common name of the peer's certificate into out (33+ bytes); PPC_ERR_TLS without one. */
int ppc_tls_peer_common_name(void *ssl, char *out, size_t out_len);
void ppc_tls_free(void *ssl);

#endif
