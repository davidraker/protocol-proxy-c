/* Payload codecs: zlib compression (section 4) and the two AEADs (section 5) through OpenSSL's EVP interface. */
#include "internal.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <zlib.h>

#define DEFAULT_MAX_DECOMPRESSED (256u * 1024u * 1024u)

int ppc_zlib_compress(const uint8_t *in, size_t len, uint8_t **out, size_t *out_len) {
    if (out == NULL || out_len == NULL) return PPC_ERR_INVALID;
    uLong bound = compressBound((uLong)len);
    uint8_t *buf = malloc(bound ? bound : 1);
    if (buf == NULL) return PPC_ERR_NOMEM;
    uLongf dest_len = bound;
    int rc = compress2(buf, &dest_len, in ? in : (const Bytef *)"", (uLong)len, Z_DEFAULT_COMPRESSION);
    if (rc != Z_OK) { free(buf); return PPC_ERR_INVALID; }
    *out = buf;
    *out_len = dest_len;
    return PPC_OK;
}

int ppc_zlib_decompress(const uint8_t *in, size_t len, uint8_t **out, size_t *out_len, size_t max_out) {
    if (out == NULL || out_len == NULL) return PPC_ERR_INVALID;
    if (max_out == 0) max_out = DEFAULT_MAX_DECOMPRESSED;
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    if (inflateInit(&zs) != Z_OK) return PPC_ERR_NOMEM;
    size_t cap = len * 4 + 64;
    if (cap > max_out) cap = max_out;
    uint8_t *buf = malloc(cap);
    if (buf == NULL) { inflateEnd(&zs); return PPC_ERR_NOMEM; }
    zs.next_in = (Bytef *)in;
    zs.avail_in = (uInt)len;
    size_t total = 0;
    int rc;
    for (;;) {
        if (total == cap) {
            if (cap >= max_out) { free(buf); inflateEnd(&zs); return PPC_ERR_PROTOCOL; }
            size_t ncap = cap * 2 > max_out ? max_out : cap * 2;
            uint8_t *nb = realloc(buf, ncap);
            if (nb == NULL) { free(buf); inflateEnd(&zs); return PPC_ERR_NOMEM; }
            buf = nb;
            cap = ncap;
        }
        zs.next_out = buf + total;
        zs.avail_out = (uInt)(cap - total);
        rc = inflate(&zs, Z_NO_FLUSH);
        total = cap - zs.avail_out;
        if (rc == Z_STREAM_END) break;
        if (rc == Z_BUF_ERROR && zs.avail_in == 0) { free(buf); inflateEnd(&zs); return PPC_ERR_INVALID; }
        if (rc != Z_OK && rc != Z_BUF_ERROR) { free(buf); inflateEnd(&zs); return PPC_ERR_INVALID; }
    }
    inflateEnd(&zs);
    *out = buf;
    *out_len = total;
    return PPC_OK;
}

static const EVP_CIPHER *aead_cipher(bool aes_gcm) {
    return aes_gcm ? EVP_aes_256_gcm() : EVP_chacha20_poly1305();
}

int ppc_aead_seal(bool aes_gcm, const uint8_t key[PPC_KEY_BYTES], const uint8_t nonce[PPC_NONCE_BYTES],
                  const uint8_t *aad, size_t aad_len, const uint8_t *plain, size_t plain_len, uint8_t *out) {
    if (key == NULL || nonce == NULL || out == NULL) return PPC_ERR_INVALID;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return PPC_ERR_NOMEM;
    int rc = PPC_ERR_INVALID, len = 0, total = 0;
    if (EVP_EncryptInit_ex(ctx, aead_cipher(aes_gcm), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, PPC_NONCE_BYTES, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (aad_len && EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto done;
    if (plain_len && EVP_EncryptUpdate(ctx, out, &len, plain, (int)plain_len) != 1) goto done;
    total = plain_len ? len : 0;
    if (EVP_EncryptFinal_ex(ctx, out + total, &len) != 1) goto done;
    total += len;
    if ((size_t)total != plain_len) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, PPC_TAG_BYTES, out + plain_len) != 1) goto done;
    rc = PPC_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int ppc_aead_open(bool aes_gcm, const uint8_t key[PPC_KEY_BYTES], const uint8_t nonce[PPC_NONCE_BYTES],
                  const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out) {
    if (key == NULL || nonce == NULL || in == NULL || out == NULL || len < PPC_TAG_BYTES) return PPC_ERR_INVALID;
    size_t ct_len = len - PPC_TAG_BYTES;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return PPC_ERR_NOMEM;
    int rc = PPC_ERR_INVALID, olen = 0, total = 0;
    if (EVP_DecryptInit_ex(ctx, aead_cipher(aes_gcm), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, PPC_NONCE_BYTES, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (aad_len && EVP_DecryptUpdate(ctx, NULL, &olen, aad, (int)aad_len) != 1) goto done;
    if (ct_len && EVP_DecryptUpdate(ctx, out, &olen, in, (int)ct_len) != 1) goto done;
    total = ct_len ? olen : 0;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, PPC_TAG_BYTES, (void *)(in + ct_len)) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, out + total, &olen) != 1) { rc = PPC_ERR_AUTH; goto done; }
    total += olen;
    rc = (size_t)total == ct_len ? PPC_OK : PPC_ERR_INVALID;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int ppc_random_bytes(uint8_t *out, size_t len) {
    if (len == 0) return PPC_OK;
    return RAND_bytes(out, (int)len) == 1 ? PPC_OK : PPC_ERR_IO;
}

bool ppc_cpu_has_aes(void) {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f == NULL) return false;
    char line[4096];
    bool found = false;
    while (!found && fgets(line, sizeof line, f)) {
        char *colon = strchr(line, ':');
        if (colon == NULL) continue;
        *colon = '\0';
        char *key = line;
        while (*key == ' ' || *key == '\t') key++;
        char *kend = key + strlen(key);
        while (kend > key && (kend[-1] == ' ' || kend[-1] == '\t')) *--kend = '\0';
        if (strcasecmp(key, "flags") != 0 && strcasecmp(key, "features") != 0) continue;
        char *save = NULL;
        for (char *tok = strtok_r(colon + 1, " \t\r\n", &save); tok; tok = strtok_r(NULL, " \t\r\n", &save))
            if (strcmp(tok, "aes") == 0) { found = true; break; }
        break;      /* the first flags line decides, as the Python reference does */
    }
    fclose(f);
    return found;
}

const char *ppc_resolve_cipher(const char *cipher) {
    if (cipher == NULL || cipher[0] == '\0' || strcmp(cipher, "auto") == 0)
        return ppc_cpu_has_aes() ? "aes-256-gcm" : PPC_BASELINE_CIPHER;
    if (strcmp(cipher, "aes-256-gcm") == 0) return "aes-256-gcm";
    if (strcmp(cipher, PPC_BASELINE_CIPHER) == 0) return PPC_BASELINE_CIPHER;
    return NULL;
}

const char *ppc_cipher_feature(const char *cipher) {
    if (cipher && strcmp(cipher, "aes-256-gcm") == 0) return "aead-aes256gcm";
    return "aead-chacha20poly1305";
}

bool ppc_cipher_is_aes_gcm(const char *cipher) { return cipher && strcmp(cipher, "aes-256-gcm") == 0; }
