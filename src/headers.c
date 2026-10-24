/* Frame headers (PROTOCOL.md section 3): version 1 `>HQ32sH16s16sH`, version 2 `>HQ32sI16s16sH16s`. */
#include "internal.h"

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)(v >> 16)); put16(p + 2, (uint16_t)v); }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)(v >> 32)); put32(p + 4, (uint32_t)v); }
static uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t get32(const uint8_t *p) { return ((uint32_t)get16(p) << 16) | get16(p + 2); }
static uint64_t get64(const uint8_t *p) { return ((uint64_t)get32(p) << 32) | get32(p + 4); }

size_t ppc_header_length(uint16_t version) {
    switch (version) {
    case 1: return 2 + PPC_HEADER_V1_LENGTH;
    case 2: return 2 + PPC_HEADER_V2_LENGTH;
    default: return 0;
    }
}

int ppc_header_pack(const ppc_header *h, uint8_t *out, size_t *out_len) {
    if (h == NULL || out == NULL) return PPC_ERR_INVALID;
    size_t method_len = strlen(h->method_name);
    if (method_len > PPC_METHOD_MAX) return PPC_ERR_INVALID;
    if (h->version == 1) {
        if (h->request_id > PPC_REQUEST_ID_MAX_V1) return PPC_ERR_INVALID;
    } else if (h->version != 2) {
        return PPC_ERR_PROTOCOL;
    }
    uint8_t *p = out;
    put16(p, h->version); p += 2;
    put64(p, h->data_length); p += 8;
    memset(p, 0, PPC_METHOD_MAX);
    memcpy(p, h->method_name, method_len); p += PPC_METHOD_MAX;
    if (h->version == 1) { put16(p, (uint16_t)h->request_id); p += 2; }
    else { put32(p, h->request_id); p += 4; }
    memcpy(p, h->sender_id.b, 16); p += 16;
    memcpy(p, h->sender_token.b, 16); p += 16;
    put16(p, h->bitflags); p += 2;
    if (h->version == 2) { memcpy(p, h->remote_id.b, 16); p += 16; }
    if (out_len) *out_len = (size_t)(p - out);
    return PPC_OK;
}

int ppc_header_unpack(const uint8_t *buf, size_t len, ppc_header *out) {
    if (buf == NULL || out == NULL || len < 2) return PPC_ERR_INVALID;
    uint16_t version = get16(buf);
    size_t need = ppc_header_length(version);
    if (need == 0) return PPC_ERR_PROTOCOL;
    if (len < need) return PPC_ERR_INVALID;
    memset(out, 0, sizeof *out);
    const uint8_t *p = buf + 2;
    out->version = version;
    out->data_length = get64(p); p += 8;
    /* method_name is NUL-padded; take the bytes up to the first NUL (Python strips trailing NULs). */
    size_t n = 0;
    while (n < PPC_METHOD_MAX && p[n] != 0) n++;
    memcpy(out->method_name, p, n);
    out->method_name[n] = '\0';
    p += PPC_METHOD_MAX;
    if (version == 1) { out->request_id = get16(p); p += 2; }
    else { out->request_id = get32(p); p += 4; }
    memcpy(out->sender_id.b, p, 16); p += 16;
    memcpy(out->sender_token.b, p, 16); p += 16;
    out->bitflags = get16(p); p += 2;
    if (version == 2) memcpy(out->remote_id.b, p, 16);
    return PPC_OK;
}
