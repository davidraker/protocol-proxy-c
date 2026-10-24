/* Small shared helpers: errors, UUIDs, hex, buffers, timestamps. */
#include "internal.h"

#include <ctype.h>
#include <stdio.h>

const char *ppc_strerror(int code) {
    switch (code) {
    case PPC_OK: return "ok";
    case PPC_ERR_INVALID: return "invalid argument or malformed data";
    case PPC_ERR_NOMEM: return "out of memory";
    case PPC_ERR_IO: return "I/O error";
    case PPC_ERR_TIMEOUT: return "timed out";
    case PPC_ERR_CONNECTION: return "connection lost or refused";
    case PPC_ERR_NO_ROUTE: return "no open connection and no address to dial";
    case PPC_ERR_AUTH: return "frame refused (authentication)";
    case PPC_ERR_STOPPED: return "stopping";
    case PPC_ERR_PROTOCOL: return "protocol error";
    case PPC_ERR_TLS: return "TLS error";
    default: return "unknown error";
    }
}

/* ---- hex ---------------------------------------------------------------------------------------------------- */
static const char HEX[] = "0123456789abcdef";

void ppc_hex_encode(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = HEX[in[i] >> 4];
        out[2 * i + 1] = HEX[in[i] & 15];
    }
    out[2 * len] = '\0';
}

static int hexval(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

int ppc_hex_decode(const char *in, size_t in_len, uint8_t *out, size_t out_len) {
    if (in_len != 2 * out_len) return PPC_ERR_INVALID;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hexval((unsigned char)in[2 * i]), lo = hexval((unsigned char)in[2 * i + 1]);
        if (hi < 0 || lo < 0) return PPC_ERR_INVALID;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return PPC_OK;
}

/* ---- UUIDs -------------------------------------------------------------------------------------------------- */
int ppc_uuid_parse(const char *text, ppc_uuid *out) {
    if (text == NULL || out == NULL) return PPC_ERR_INVALID;
    char digits[33];
    size_t n = 0;
    for (const char *p = text; *p; p++) {
        if (*p == '-' || *p == '{' || *p == '}') continue;
        if (n == 32 || hexval((unsigned char)*p) < 0) return PPC_ERR_INVALID;
        digits[n++] = *p;
    }
    if (n != 32) return PPC_ERR_INVALID;
    return ppc_hex_decode(digits, 32, out->b, 16);
}

void ppc_uuid_hex(const ppc_uuid *id, char out[33]) { ppc_hex_encode(id->b, 16, out); }

void ppc_uuid_str(const ppc_uuid *id, char out[37]) {
    char hex[33];
    ppc_hex_encode(id->b, 16, hex);
    snprintf(out, 37, "%.8s-%.4s-%.4s-%.4s-%.12s", hex, hex + 8, hex + 12, hex + 16, hex + 20);
}

bool ppc_uuid_equal(const ppc_uuid *a, const ppc_uuid *b) { return memcmp(a->b, b->b, 16) == 0; }

bool ppc_uuid_is_nil(const ppc_uuid *id) {
    static const ppc_uuid nil = {{0}};
    return ppc_uuid_equal(id, &nil);
}

int ppc_uuid_random(ppc_uuid *out) {
    int rc = ppc_random_bytes(out->b, 16);
    if (rc != PPC_OK) return rc;
    out->b[6] = (uint8_t)((out->b[6] & 0x0f) | 0x40);    /* version 4 */
    out->b[8] = (uint8_t)((out->b[8] & 0x3f) | 0x80);    /* RFC 4122 variant */
    return PPC_OK;
}

/* ---- buffers ------------------------------------------------------------------------------------------------ */
int ppc_buf_reserve(ppc_buf *b, size_t extra) {
    if (b->len + extra <= b->cap) return PPC_OK;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + extra) cap *= 2;
    uint8_t *data = realloc(b->data, cap);
    if (data == NULL) return PPC_ERR_NOMEM;
    b->data = data;
    b->cap = cap;
    return PPC_OK;
}

int ppc_buf_append(ppc_buf *b, const void *data, size_t len) {
    int rc = ppc_buf_reserve(b, len);
    if (rc != PPC_OK) return rc;
    if (len) memcpy(b->data + b->len, data, len);
    b->len += len;
    return PPC_OK;
}

void ppc_buf_free(ppc_buf *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

/* ---- time --------------------------------------------------------------------------------------------------- */
void ppc_iso8601(double when, char *out, size_t out_len) {
    time_t secs = (time_t)when;
    long micros = (long)((when - (double)secs) * 1e6 + 0.5);
    if (micros >= 1000000) { secs += 1; micros -= 1000000; }
    if (micros < 0) micros = 0;
    struct tm tm;
    gmtime_r(&secs, &tm);
    char date[32];
    strftime(date, sizeof date, "%Y-%m-%dT%H:%M:%S", &tm);
    if (micros)
        snprintf(out, out_len, "%s.%06ld+00:00", date, micros);
    else
        snprintf(out, out_len, "%s+00:00", date);
}
