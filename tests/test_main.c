/* Unit tests: headers against the vectors, JSON, compression, AEAD, option parsing, the stdin handshake, loopback
 * request/response between two connectors in one process (per-message, persistent, adoption, errors, encryption,
 * compression, the large-frame rule), manifests, log records, the certificate authority, and the manager against
 * bin/echo-proxy (launch, PING/ECHO/SET_LOG_LEVEL/LOG, relaunch, heartbeat loss, TLS and encryption, manager-dials,
 * process keys, registration timeout, the conformance harness). Run by `make test` under the sanitizers. */
#include "ppc/ppc.h"

#include <arpa/inet.h>
#include <limits.h>
#include <malloc.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

/* ---- the LOG queue (sections 9, 11a) --------------------------------------------------------------------------- */
static char *record(const char *msg) {
    return ppc_log_record_json(PPC_LOG_INFO, "t", "x.c", 1, "f", msg);
}

static void test_log_queue(void) {
    /* Bounded: beyond max_len records are dropped and counted; drain hands back what was kept, in order. */
    ppc_log_queue *q = ppc_log_queue_new(5, 1e9, 1000000);
    int kept = 0;
    for (int i = 0; i < 8; i++) {
        char text[16];
        snprintf(text, sizeof text, "r%d", i);
        if (ppc_log_queue_push(q, record(text))) kept++;
    }
    CHECK(kept == 5 && ppc_log_queue_len(q) == 5, "bounded: kept %d, len %zu", kept, ppc_log_queue_len(q));
    size_t count = 0;
    long dropped = 0;
    char **taken = ppc_log_queue_drain(q, 0, &count, &dropped);
    CHECK(count == 5 && dropped == 3, "bounded drain: %zu records, %ld dropped", count, dropped);
    CHECK(taken && strstr(taken[0], "\"msg\": \"r0\"") && strstr(taken[4], "\"msg\": \"r4\""), "drain keeps order");
    for (size_t i = 0; i < count; i++) free(taken[i]);
    free(taken);
    taken = ppc_log_queue_drain(q, 0, &count, &dropped);
    CHECK(taken == NULL && count == 0 && dropped == 0, "empty drain resets the dropped count");
    CHECK(ppc_log_queue_total_dropped(q) == 3, "total dropped %ld", ppc_log_queue_total_dropped(q));
    ppc_log_queue_free(q);

    /* Rate limited: a burst of 3, then 10 per second. */
    q = ppc_log_queue_new(1000, 10, 3);
    kept = 0;
    for (int i = 0; i < 6; i++) if (ppc_log_queue_push(q, record("burst"))) kept++;
    CHECK(kept == 3, "burst: kept %d of 6", kept);
    usleep(150000);                                 /* 1.5 tokens refilled */
    CHECK(ppc_log_queue_push(q, record("refilled")), "a token refills at the rate");
    CHECK(!ppc_log_queue_push(q, record("too soon")), "the next record waits for the rate");
    taken = ppc_log_queue_drain(q, 2, &count, &dropped);
    CHECK(count == 2 && dropped == 4 && ppc_log_queue_len(q) == 2, "limited drain: %zu taken, %ld dropped, %zu left", count, dropped, ppc_log_queue_len(q));
    char *batch = ppc_log_batch_json(taken, count, dropped);
    char err[64];
    ppc_json *v = ppc_json_parse(batch, strlen(batch), err, sizeof err);
    const ppc_json *records = ppc_json_get(v, "records");
    CHECK(v && records && records->type == PPC_JSON_ARRAY && records->count == 2 && ppc_json_get_number(v, "dropped", -1) == 4,
          "batch JSON: %s", batch);
    CHECK(records && records->count == 2 && strcmp(ppc_json_get_string(records->items[0], "msg", ""), "burst") == 0, "batch keeps the records");
    ppc_json_free(v);
    free(batch);
    for (size_t i = 0; i < count; i++) free(taken[i]);
    free(taken);
    ppc_log_queue_free(q);                          /* frees the two records still queued */
    batch = ppc_log_batch_json(NULL, 0, 0);
    CHECK(batch && strcmp(batch, "{\"records\": [], \"dropped\": 0}") == 0, "empty batch: %s", batch ? batch : "");
    free(batch);

    /* The sink: with a queue installed, JSON records are queued instead of written; levels still gate them. */
    ppc_log_init("INFO", 1, "test");
    q = ppc_log_queue_new(0, 0, 0);
    ppc_log_set_queue(q);
    PPC_LOG_AT(PPC_LOG_DEBUG, "t", "not %s", "logged");
    PPC_LOG_AT(PPC_LOG_WARNING, "t", "queued %d", 1);
    ppc_log_set_queue(NULL);
    PPC_LOG_AT(PPC_LOG_WARNING, "t", "back on stderr (expected in the test output)");
    taken = ppc_log_queue_drain(q, 0, &count, &dropped);
    CHECK(count == 1 && dropped == 0 && taken && strstr(taken[0], "\"msg\": \"queued 1\"") && strstr(taken[0], "\"levelname\": \"WARNING\""),
          "sink: %zu queued, %s", count, count ? taken[0] : "");
    for (size_t i = 0; i < count; i++) free(taken[i]);
    free(taken);
    ppc_log_queue_free(q);
    ppc_log_init("WARNING", 0, "test");
}

/* ---- JSON ----------------------------------------------------------------------------------------------------- */
static void test_json(void) {
    char err[128];
    const char *text = "{\"a\": [1, 2.5, -3, true, false, null, \"h\\u00e9llo \\\"q\\\" \\n\\ud83d\\ude00\"], \"b\": {\"c\": {}}, \"d\": []}";
    ppc_json *v = ppc_json_parse(text, strlen(text), err, sizeof err);
    CHECK(v != NULL, "parse: %s", err);
    if (v) {
        const ppc_json *a = ppc_json_get(v, "a");
        CHECK(a && a->type == PPC_JSON_ARRAY && a->count == 7, "array");
        CHECK(a && a->items[0]->is_integer && a->items[0]->integer == 1, "integer");
        CHECK(a && !a->items[1]->is_integer && a->items[1]->number == 2.5, "float");
        CHECK(a && a->items[2]->integer == -3, "negative");
        CHECK(a && a->items[3]->boolean && !a->items[4]->boolean && a->items[5]->type == PPC_JSON_NULL, "literals");
        CHECK(a && strcmp(a->items[6]->string, "h\xc3\xa9llo \"q\" \n\xf0\x9f\x98\x80") == 0, "string escapes: %s", a ? a->items[6]->string : "");
        char *dumped = ppc_json_dump(v);
        const char *expected = "{\"a\": [1, 2.5, -3, true, false, null, \"h\\u00e9llo \\\"q\\\" \\n\\ud83d\\ude00\"], \"b\": {\"c\": {}}, \"d\": []}";
        CHECK(dumped && strcmp(dumped, expected) == 0, "dump:\n  %s\n  %s", dumped ? dumped : "", expected);
        free(dumped);
        ppc_json_free(v);
    }
    /* Python float repr. */
    ppc_json *n = ppc_json_new_number(12.345);
    char *d = ppc_json_dump(n);
    CHECK(d && strcmp(d, "12.345") == 0, "12.345 -> %s", d ? d : "");
    free(d); ppc_json_free(n);
    n = ppc_json_new_number(1760000000.5);
    d = ppc_json_dump(n);
    CHECK(d && strcmp(d, "1760000000.5") == 0, "1760000000.5 -> %s", d ? d : "");
    free(d); ppc_json_free(n);
    n = ppc_json_new_number(3.0);
    d = ppc_json_dump(n);
    CHECK(d && strcmp(d, "3.0") == 0, "3.0 -> %s", d ? d : "");
    free(d); ppc_json_free(n);
    n = ppc_json_new_number(0.1);
    d = ppc_json_dump(n);
    CHECK(d && strcmp(d, "0.1") == 0, "0.1 -> %s", d ? d : "");
    free(d); ppc_json_free(n);
    /* Malformed input. */
    CHECK(ppc_json_parse("{\"a\": }", 7, err, sizeof err) == NULL, "malformed accepted");
    CHECK(ppc_json_parse("[1, 2", 5, err, sizeof err) == NULL, "unterminated accepted");
    CHECK(ppc_json_parse("{} x", 4, err, sizeof err) == NULL, "trailing data accepted");
    CHECK(ppc_json_parse("\"\\x\"", 4, err, sizeof err) == NULL, "bad escape accepted");
    v = ppc_json_parse("true", 4, err, sizeof err);
    CHECK(v && v->type == PPC_JSON_BOOL && v->boolean, "bare true");
    ppc_json_free(v);
    /* Object set replaces. */
    v = ppc_json_new_object();
    ppc_json_object_set(v, "k", ppc_json_new_integer(1));
    ppc_json_object_set(v, "k", ppc_json_new_integer(2));
    CHECK(v->count == 1 && v->items[0]->integer == 2, "object set replace");
    ppc_json_free(v);
}

/* ---- codecs --------------------------------------------------------------------------------------------------- */
static void test_codecs(void) {
    uint8_t *data = malloc(100000);
    for (size_t i = 0; i < 100000; i++) data[i] = (uint8_t)('a' + i % 7);
    uint8_t *z = NULL, *back = NULL;
    size_t zlen = 0, blen = 0;
    CHECK(ppc_zlib_compress(data, 100000, &z, &zlen) == PPC_OK && zlen < 2000, "compress 100 KB -> %zu", zlen);
    CHECK(ppc_zlib_decompress(z, zlen, &back, &blen, 0) == PPC_OK && blen == 100000 && memcmp(back, data, blen) == 0, "decompress");
    free(back); back = NULL;
    CHECK(ppc_zlib_decompress(z, zlen, &back, &blen, 1000) == PPC_ERR_PROTOCOL, "decompression bound");
    free(back); back = NULL;
    z[zlen / 2] ^= 0xff;
    int rc = ppc_zlib_decompress(z, zlen, &back, &blen, 0);
    CHECK(rc != PPC_OK, "corrupt zlib accepted");
    if (rc == PPC_OK) free(back);
    back = NULL;
    free(z);
    CHECK(ppc_zlib_compress(NULL, 0, &z, &zlen) == PPC_OK && zlen > 0, "compress empty");
    CHECK(ppc_zlib_decompress(z, zlen, &back, &blen, 0) == PPC_OK && blen == 0, "decompress empty");
    free(z); free(back);

    uint8_t key[32], nonce[12];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(100 + i);
    const uint8_t aad[] = "header bytes";
    for (int aes = 0; aes < 2; aes++) {
        uint8_t sealed[100000 + 16], opened[100000];
        CHECK(ppc_aead_seal(aes, key, nonce, aad, sizeof aad, data, 100000, sealed) == PPC_OK, "seal aes=%d", aes);
        CHECK(ppc_aead_open(aes, key, nonce, aad, sizeof aad, sealed, sizeof sealed, opened) == PPC_OK
              && memcmp(opened, data, 100000) == 0, "open aes=%d", aes);
        sealed[5] ^= 1;
        CHECK(ppc_aead_open(aes, key, nonce, aad, sizeof aad, sealed, sizeof sealed, opened) == PPC_ERR_AUTH, "tampered ciphertext aes=%d", aes);
        sealed[5] ^= 1;
        sealed[100000 + 3] ^= 1;
        CHECK(ppc_aead_open(aes, key, nonce, aad, sizeof aad, sealed, sizeof sealed, opened) == PPC_ERR_AUTH, "tampered tag aes=%d", aes);
        sealed[100000 + 3] ^= 1;
        CHECK(ppc_aead_open(aes, key, nonce, aad, sizeof aad - 1, sealed, sizeof sealed, opened) == PPC_ERR_AUTH, "tampered aad aes=%d", aes);
        uint8_t other[12] = {0};
        CHECK(ppc_aead_open(aes, key, other, aad, sizeof aad, sealed, sizeof sealed, opened) == PPC_ERR_AUTH, "wrong nonce aes=%d", aes);
        /* Empty plaintext. */
        uint8_t tag_only[16], none[1];
        CHECK(ppc_aead_seal(aes, key, nonce, aad, sizeof aad, NULL, 0, tag_only) == PPC_OK, "seal empty aes=%d", aes);
        CHECK(ppc_aead_open(aes, key, nonce, aad, sizeof aad, tag_only, 16, none) == PPC_OK, "open empty aes=%d", aes);
        CHECK(ppc_aead_open(aes, key, nonce, aad, sizeof aad, tag_only, 15, none) == PPC_ERR_INVALID, "short ciphertext aes=%d", aes);
    }
    free(data);
    CHECK(strcmp(ppc_resolve_cipher("chacha20-poly1305"), "chacha20-poly1305") == 0, "resolve chacha");
    CHECK(strcmp(ppc_resolve_cipher("aes-256-gcm"), "aes-256-gcm") == 0, "resolve aes");
    CHECK(ppc_resolve_cipher("rot13") == NULL, "resolve unknown");
    const char *auto_cipher = ppc_resolve_cipher("auto");
    CHECK(auto_cipher && (strcmp(auto_cipher, "aes-256-gcm") == 0 || strcmp(auto_cipher, "chacha20-poly1305") == 0), "resolve auto");
    CHECK(strcmp(ppc_cipher_feature("aes-256-gcm"), "aead-aes256gcm") == 0 && ppc_cipher_is_aes_gcm("aes-256-gcm"), "aes feature");
    CHECK(strcmp(ppc_cipher_feature("chacha20-poly1305"), "aead-chacha20poly1305") == 0 && !ppc_cipher_is_aes_gcm("chacha20-poly1305"), "chacha feature");
}

/* ---- headers beyond the vectors ------------------------------------------------------------------------------- */
static void test_headers(void) {
    ppc_header h;
    memset(&h, 0, sizeof h);
    h.version = 1;
    h.request_id = 70000;
    strcpy(h.method_name, "PING");
    uint8_t out[PPC_FRAME_HEADER_MAX];
    size_t n;
    CHECK(ppc_header_pack(&h, out, &n) == PPC_ERR_INVALID, "v1 request id overflow accepted");
    h.version = 3;
    CHECK(ppc_header_pack(&h, out, &n) == PPC_ERR_PROTOCOL, "unknown version packed");
    h.version = 2;
    memset(h.method_name, 'M', 32);
    h.method_name[32] = 0;
    CHECK(ppc_header_pack(&h, out, &n) == PPC_OK && n == 96, "32-byte method");
    ppc_header u;
    CHECK(ppc_header_unpack(out, n, &u) == PPC_OK && strcmp(u.method_name, h.method_name) == 0, "32-byte method unpack");
    out[0] = 0; out[1] = 9;
    CHECK(ppc_header_unpack(out, n, &u) == PPC_ERR_PROTOCOL, "unknown version unpacked");
    out[1] = 2;
    CHECK(ppc_header_unpack(out, 50, &u) == PPC_ERR_INVALID, "short header unpacked");
    CHECK(ppc_header_length(1) == 78 && ppc_header_length(2) == 96 && ppc_header_length(7) == 0, "header lengths");
    ppc_uuid id;
    CHECK(ppc_uuid_parse("11111111-2222-3333-4444-555555555555", &id) == PPC_OK && id.b[0] == 0x11 && id.b[15] == 0x55, "uuid parse dashed");
    CHECK(ppc_uuid_parse("11111111222233334444555555555555", &id) == PPC_OK, "uuid parse plain");
    CHECK(ppc_uuid_parse("1111", &id) == PPC_ERR_INVALID && ppc_uuid_parse("zz111111222233334444555555555555", &id) == PPC_ERR_INVALID, "uuid parse bad");
    char s[37];
    ppc_uuid_str(&id, s);
    CHECK(strcmp(s, "11111111-2222-3333-4444-555555555555") == 0, "uuid str %s", s);
    CHECK(ppc_uuid_random(&id) == PPC_OK && (id.b[6] >> 4) == 4, "uuid random");
}

/* ---- options and the stdin handshake -------------------------------------------------------------------------- */
static void test_options(void) {
    char *argv[] = {"echo-proxy", "--proxy-id", "11111111222233334444555555555555", "--proxy-name", "('conformance',)",
                    "--manager-id", "99999999888877776666555555555555", "--manager-address", "127.0.0.1", "--manager-port", "22801",
                    "--encrypt", "True", "--cipher", "aes-256-gcm", "--manager-dials", "false", "--persistent", "1",
                    "--inbound-address", "127.0.0.1", "--inbound-port", "22850", "--log-level", "DEBUG", "--compress-threshold", "100",
                    "--device-host", "10.0.0.1", "--socket-logging=false"};
    int argc = (int)(sizeof argv / sizeof *argv);
    ppc_proxy_options o;
    char err[256];
    CHECK(ppc_proxy_options_parse(argc, argv, &o, err, sizeof err) == PPC_OK, "parse: %s", err);
    CHECK(strcmp(o.proxy_name, "('conformance',)") == 0 && o.manager_port == 22801 && o.encrypt && !o.manager_dials && o.persistent
          && o.inbound_port == 22850 && strcmp(o.cipher, "aes-256-gcm") == 0 && strcmp(o.log_level, "DEBUG") == 0
          && o.compress_threshold == 100 && !o.socket_logging, "option values");
    CHECK(o.extra_count == 1 && strcmp(ppc_proxy_option(&o, "device_host"), "10.0.0.1") == 0, "extra option");
    ppc_proxy_options_free(&o);
    char *missing[] = {"echo-proxy", "--proxy-id", "11111111222233334444555555555555"};
    CHECK(ppc_proxy_options_parse(3, missing, &o, err, sizeof err) == PPC_ERR_INVALID, "missing required accepted");
    ppc_proxy_options_free(&o);
    char *bad_bool[] = {"echo-proxy", "--proxy-id", "11111111222233334444555555555555", "--proxy-name", "x", "--manager-id",
                        "99999999888877776666555555555555", "--encrypt", "maybe"};
    CHECK(ppc_proxy_options_parse(9, bad_bool, &o, err, sizeof err) == PPC_ERR_INVALID, "bad boolean accepted");
    ppc_proxy_options_free(&o);
    char *dangling[] = {"echo-proxy", "--proxy-id"};
    CHECK(ppc_proxy_options_parse(2, dangling, &o, err, sizeof err) == PPC_ERR_INVALID, "dangling option accepted");
    ppc_proxy_options_free(&o);

    /* stdin: tokens, key, TLS line. */
    const char *stdin_text = "aaaaaaaabbbbccccddddeeeeeeeeeeee" "11111111222233334444555555555555"
                             "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                             "{\"ca\": \"CA\", \"cert\": \"CERT\", \"key\": \"KEY\"}\n";
    FILE *f = fmemopen((void *)stdin_text, strlen(stdin_text), "r");
    ppc_proxy_secrets s;
    CHECK(ppc_proxy_read_secrets(f, true, true, &s, err, sizeof err) == PPC_OK, "secrets: %s", err);
    CHECK(s.proxy_token.b[0] == 0xaa && s.manager_token.b[0] == 0x11 && s.has_key && s.key[31] == 0x1f && s.tls
          && strcmp(s.tls->cert, "CERT") == 0, "secret values");
    ppc_proxy_secrets_free(&s);
    fclose(f);
    f = fmemopen((void *)stdin_text, 64, "r");
    CHECK(ppc_proxy_read_secrets(f, true, false, &s, err, sizeof err) == PPC_ERR_INVALID, "missing key accepted");
    fclose(f);
    f = fmemopen((void *)stdin_text, 10, "r");
    CHECK(ppc_proxy_read_secrets(f, false, false, &s, err, sizeof err) == PPC_ERR_INVALID, "short tokens accepted");
    fclose(f);
    CHECK(ppc_log_level_from_name("debug") == 10 && ppc_log_level_from_name("WARN") == 30 && ppc_log_level_from_name("40") == 40
          && ppc_log_level_from_name("nope") == -1, "level names");
}

/* ---- loopback ------------------------------------------------------------------------------------------------- */
typedef struct {
    uint32_t last_request_id;
    uint16_t last_version;
    int calls;
} echo_state;

static int echo_handler(ppc_connector *c, const ppc_header *h, const uint8_t *payload, size_t len, uint8_t **reply,
                        size_t *reply_len, void *user) {
    (void)c;
    echo_state *st = user;
    st->last_request_id = h->request_id;
    st->last_version = h->version;
    st->calls++;
    uint8_t *copy = malloc(len ? len : 1);
    memcpy(copy, payload, len);
    *reply = copy;
    *reply_len = len;
    return PPC_OK;
}

static int silent_handler(ppc_connector *c, const ppc_header *h, const uint8_t *payload, size_t len, uint8_t **reply,
                          size_t *reply_len, void *user) {
    (void)c; (void)h; (void)payload; (void)len; (void)reply; (void)reply_len;
    (*(int *)user)++;
    return PPC_OK;
}

static int failing_handler(ppc_connector *c, const ppc_header *h, const uint8_t *payload, size_t len, uint8_t **reply,
                           size_t *reply_len, void *user) {
    (void)c; (void)h; (void)payload; (void)len; (void)reply; (void)reply_len; (void)user;
    return PPC_ERR_IO;
}

static ppc_connector *make_connector(const char *name, const ppc_uuid *id, const ppc_uuid *token, bool persistent) {
    ppc_connector_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.proxy_id = *id;
    cfg.token = *token;
    cfg.proxy_name = name;
    cfg.inbound_address = "127.0.0.1";
    cfg.persistent = persistent;
    cfg.io_timeout = 5;
    cfg.cipher = "chacha20-poly1305";
    ppc_connector *c = ppc_connector_new(&cfg);
    CHECK(c != NULL, "%s: connector", name);
    CHECK(ppc_connector_start(c) == PPC_OK, "%s: start", name);
    return c;
}

static int request_text(ppc_connector *c, ppc_peer *peer, const char *method, const char *text, int version, uint8_t **reply, size_t *len) {
    ppc_message m = {method, (const uint8_t *)text, strlen(text), true, NULL, version, false};
    return ppc_connector_request(c, peer, &m, 5.0, reply, len);
}

static void test_loopback(bool persistent, bool encrypted) {
    const char *mode = persistent ? (encrypted ? "persistent+encrypted" : "persistent") : (encrypted ? "per-message+encrypted" : "per-message");
    ppc_uuid id_a, id_b, tok_a, tok_b;
    ppc_uuid_random(&id_a); ppc_uuid_random(&id_b); ppc_uuid_random(&tok_a); ppc_uuid_random(&tok_b);
    uint8_t key[32];
    ppc_random_bytes(key, 32);
    ppc_connector *a = make_connector("A", &id_a, &tok_a, persistent);
    ppc_connector *b = make_connector("B", &id_b, &tok_b, persistent);
    char addr_a[64];
    int port_a = 0;
    ppc_connector_local_address(a, addr_a, sizeof addr_a, &port_a);
    CHECK(port_a >= 22801 && port_a <= 22899 && strcmp(addr_a, "127.0.0.1") == 0, "%s: A listens at %s:%d", mode, addr_a, port_a);
    echo_state state_a = {0}, state_b = {0};
    int silent_calls = 0;
    ppc_connector_register_handler(a, "ECHO", NULL, echo_handler, &state_a, true);
    ppc_connector_register_handler(a, "SILENT", NULL, silent_handler, &silent_calls, false);
    ppc_connector_register_handler(a, "FAIL", NULL, failing_handler, NULL, true);
    ppc_connector_register_handler(b, "ECHO", NULL, echo_handler, &state_b, true);
    /* A knows B only through the connections B opens (no address); B dials A. */
    ppc_peer *b_on_a = ppc_connector_add_peer(a, &id_b, &tok_b, NULL, 0, encrypted ? key : NULL, -1, false);
    ppc_peer *a_on_b = ppc_connector_add_peer(b, &id_a, &tok_a, addr_a, port_a, encrypted ? key : NULL, -1, false);
    const char *compress_features[] = {"compress"};
    ppc_peer_set_features(a_on_b, compress_features, 1);
    ppc_peer_set_features(b_on_a, compress_features, 1);

    uint8_t *reply = NULL;
    size_t len = 0;
    int rc = request_text(b, a_on_b, "ECHO", "{\"n\": 1}", 2, &reply, &len);
    CHECK(rc == PPC_OK && len == 8 && memcmp(reply, "{\"n\": 1}", 8) == 0, "%s: echo (%s)", mode, ppc_strerror(rc));
    CHECK(state_a.last_request_id == 1 && state_a.last_version == 2, "%s: first request id is 1 (got %u)", mode, state_a.last_request_id);
    free(reply); reply = NULL;
    rc = request_text(b, a_on_b, "ECHO", "{\"n\": 2}", 1, &reply, &len);
    CHECK(rc == PPC_OK && len == 8 && state_a.last_version == 1 && state_a.last_request_id == 1, "%s: version 1 request (%s)", mode, ppc_strerror(rc));
    free(reply); reply = NULL;
    rc = request_text(b, a_on_b, "ECHO", "", 2, &reply, &len);
    CHECK(rc == PPC_OK && len == 0, "%s: empty payload echo (%s)", mode, ppc_strerror(rc));
    free(reply); reply = NULL;
    /* Unknown method and a handler without a response: the error reply of section 8, at once. */
    rc = request_text(b, a_on_b, "NOPE", "{}", 2, &reply, &len);
    CHECK(rc == PPC_OK && reply && strstr((char *)reply, "\"status\": \"error\"") && strstr((char *)reply, "Unknown method NOPE")
          && strstr((char *)reply, "\"method\": \"NOPE\""), "%s: unknown method reply %s", mode, reply ? (char *)reply : ppc_strerror(rc));
    free(reply); reply = NULL;
    rc = request_text(b, a_on_b, "SILENT", "{}", 2, &reply, &len);
    CHECK(rc == PPC_OK && reply && strstr((char *)reply, "provides no response") && silent_calls == 1, "%s: no-response handler reply %s", mode, reply ? (char *)reply : ppc_strerror(rc));
    free(reply); reply = NULL;
    rc = request_text(b, a_on_b, "FAIL", "{}", 2, &reply, &len);
    CHECK(rc == PPC_OK && reply && strstr((char *)reply, "\"status\": \"error\"") && strstr((char *)reply, "\"method\": \"FAIL\""), "%s: failing handler reply", mode);
    free(reply); reply = NULL;
    /* No response expected. */
    ppc_message push = {"SILENT", (const uint8_t *)"{}", 2, false, NULL, 2, false};
    CHECK(ppc_connector_send(b, a_on_b, &push) == PPC_OK, "%s: push", mode);
    for (int i = 0; i < 100 && silent_calls < 2; i++) usleep(10000);
    CHECK(silent_calls == 2, "%s: push delivered (%d)", mode, silent_calls);
    /* A low-priority frame (a LOG batch) is delivered too, on either connection policy. */
    ppc_message low = {"SILENT", (const uint8_t *)"{}", 2, false, NULL, 2, true};
    CHECK(ppc_connector_send(b, a_on_b, &low) == PPC_OK, "%s: low-priority push", mode);
    for (int i = 0; i < 100 && silent_calls < 3; i++) usleep(10000);
    CHECK(silent_calls == 3, "%s: low-priority push delivered (%d)", mode, silent_calls);
    /* A payload above the compression threshold round-trips (compressed on the wire toward a peer advertising it). */
    size_t big = 20000;
    char *big_text = malloc(big + 1);
    memset(big_text, 'x', big);
    big_text[0] = '"'; big_text[big - 1] = '"'; big_text[big] = 0;
    rc = request_text(b, a_on_b, "ECHO", big_text, 2, &reply, &len);
    CHECK(rc == PPC_OK && len == big && memcmp(reply, big_text, big) == 0, "%s: 20 KB echo (%s)", mode, ppc_strerror(rc));
    free(reply); reply = NULL;
    free(big_text);
    /* Above the persistent threshold: its own connection. */
    size_t huge = 300000;
    char *huge_text = malloc(huge + 1);
    for (size_t i = 0; i < huge; i++) huge_text[i] = (char)('a' + (i * 7919) % 26);
    huge_text[huge] = 0;
    rc = request_text(b, a_on_b, "ECHO", huge_text, 2, &reply, &len);
    CHECK(rc == PPC_OK && len == huge && memcmp(reply, huge_text, huge) == 0, "%s: 300 KB echo (%s)", mode, ppc_strerror(rc));
    free(reply); reply = NULL;
    free(huge_text);
    if (persistent) {
        CHECK(ppc_peer_linked(a_on_b), "%s: B holds a persistent connection to A", mode);
        CHECK(ppc_peer_linked(b_on_a), "%s: A adopted B's connection", mode);
        /* A sends back to B on the adopted connection (B has no address on A). */
        rc = request_text(a, b_on_a, "ECHO", "{\"back\": true}", 2, &reply, &len);
        CHECK(rc == PPC_OK && len == 14 && state_b.calls == 1, "%s: request back over the adopted connection (%s)", mode, ppc_strerror(rc));
        free(reply); reply = NULL;
    } else {
        CHECK(!ppc_peer_linked(a_on_b) && !ppc_peer_linked(b_on_a), "%s: no persistent connections", mode);
        rc = request_text(a, b_on_a, "ECHO", "{}", 2, &reply, &len);
        CHECK(rc == PPC_ERR_NO_ROUTE, "%s: no route to a peer without address or connection (%s)", mode, ppc_strerror(rc));
        free(reply); reply = NULL;
    }
    /* A wrong token: the frame is dropped and the request gets an empty reply. */
    ppc_uuid id_c, tok_c;
    ppc_uuid_random(&id_c); ppc_uuid_random(&tok_c);
    ppc_connector *imp = make_connector("Impostor", &id_c, &tok_c, false);
    ppc_peer *a_on_imp = ppc_connector_add_peer(imp, &id_a, &tok_a, addr_a, port_a, NULL, -1, false);
    rc = request_text(imp, a_on_imp, "ECHO", "{}", 2, &reply, &len);
    CHECK(rc == PPC_OK && len == 0 && state_a.calls == 5, "%s: unknown sender refused (%s, len %zu, calls %d)", mode, ppc_strerror(rc), len, state_a.calls);
    free(reply); reply = NULL;
    ppc_connector_free(imp);
    if (encrypted) {
        /* A clear-text sender who should encrypt: refused, connection dropped. */
        ppc_connector *clear = make_connector("Clear", &id_b, &tok_b, false);
        ppc_peer *a_on_clear = ppc_connector_add_peer(clear, &id_a, &tok_a, addr_a, port_a, NULL, -1, false);
        rc = request_text(clear, a_on_clear, "ECHO", "{}", 2, &reply, &len);
        CHECK(rc == PPC_ERR_CONNECTION && state_a.calls == 5, "%s: clear text toward an encrypting peer refused (%s)", mode, ppc_strerror(rc));
        free(reply); reply = NULL;
        ppc_connector_free(clear);
        /* A wrong key: authentication fails. */
        uint8_t other_key[32];
        memcpy(other_key, key, 32);
        other_key[0] ^= 1;
        ppc_connector *wrong = make_connector("WrongKey", &id_b, &tok_b, false);
        ppc_peer *a_on_wrong = ppc_connector_add_peer(wrong, &id_a, &tok_a, addr_a, port_a, other_key, -1, false);
        rc = request_text(wrong, a_on_wrong, "ECHO", "{}", 2, &reply, &len);
        CHECK(rc == PPC_ERR_CONNECTION && state_a.calls == 5, "%s: wrong key refused (%s)", mode, ppc_strerror(rc));
        free(reply); reply = NULL;
        ppc_connector_free(wrong);
    }
    /* Stopping A fails B's pending requests and B's link; a request from B then fails with a connection error. */
    ppc_connector_stop(a);
    rc = request_text(b, a_on_b, "ECHO", "{}", 2, &reply, &len);
    CHECK(rc == PPC_ERR_CONNECTION || rc == PPC_ERR_TIMEOUT, "%s: request to a stopped peer fails (%s)", mode, ppc_strerror(rc));
    free(reply);
    ppc_connector_free(a);
    ppc_connector_free(b);
}

/* Without a leak checker installed, watch the heap: many request/response cycles must not grow it. */
static void test_heap_growth(void) {
    ppc_uuid id_a, id_b, tok_a, tok_b;
    ppc_uuid_random(&id_a); ppc_uuid_random(&id_b); ppc_uuid_random(&tok_a); ppc_uuid_random(&tok_b);
    uint8_t key[32];
    ppc_random_bytes(key, 32);
    ppc_connector *a = make_connector("A", &id_a, &tok_a, false);
    ppc_connector *b = make_connector("B", &id_b, &tok_b, false);
    char addr_a[64];
    int port_a = 0;
    ppc_connector_local_address(a, addr_a, sizeof addr_a, &port_a);
    echo_state state_a = {0};
    ppc_connector_register_handler(a, "ECHO", NULL, echo_handler, &state_a, true);
    ppc_connector_add_peer(a, &id_b, &tok_b, NULL, 0, key, -1, false);
    ppc_peer *a_on_b = ppc_connector_add_peer(b, &id_a, &tok_a, addr_a, port_a, key, 1, false);
    const char *compress_features[] = {"compress"};
    ppc_peer_set_features(a_on_b, compress_features, 1);
    char *text = malloc(10001);
    memset(text, 'q', 10000);
    text[10000] = 0;
    for (int round = 0; round < 2; round++) {
        size_t before = mallinfo2().uordblks;
        for (int i = 0; i < 300; i++) {
            uint8_t *reply = NULL;
            size_t len = 0;
            int rc = request_text(b, a_on_b, i % 2 ? "ECHO" : "NOPE", i % 3 ? text : "{}", 2, &reply, &len);
            if (rc != PPC_OK) { CHECK(false, "heap test request %d failed: %s", i, ppc_strerror(rc)); break; }
            free(reply);
        }
        size_t after = mallinfo2().uordblks;
        /* Round 0 warms caches (OpenSSL, zlib, thread bookkeeping); round 1 must be flat. */
        if (round == 1) CHECK(after <= before + 16384, "heap grew by %zd bytes over 300 requests", (ssize_t)after - (ssize_t)before);
    }
    free(text);
    ppc_connector_free(a);
    ppc_connector_free(b);
}


/* ---- manifests (section 1a) ----------------------------------------------------------------------------------- */
static const char *const MANIFEST_TEXT =
    "[proxy]\n"
    "name = \"mqtt\"\n"
    "command = [\"{python}\", \"-m\", \"protocol_proxy.proxy\", \"--gevent\", \"protocol_proxy.protocol.mqtt.mqtt_proxy:MQTTProxy\"]\n"
    "header_version = 2\n"
    "[identity]\n"
    "keys = [\"host\", \"port\"]\n"
    "must_match = [\"username\", \"password\"]\n"
    "[identity.normalize]\n"
    "host = [\"strip\", \"lowercase\"]\n"
    "port = [{ default = 1883 }]\n"
    "[environment]\n"
    "MQTT_LOG = \"info\"\n"
    "PYTHONPATH = \"{manifest_dir}/..:{python}-site\"\n"
    "[self_test]\n"
    "command = [\"{manifest_dir}/bin/mqtt-proxy\", \"--self-test\"]\n";

static void test_manifest(void) {
    char err[512];
    ppc_manifest *m = ppc_manifest_parse(MANIFEST_TEXT, "/opt/mqtt/proxy.toml", err, sizeof err);
    CHECK(m != NULL, "parse: %s", err);
    if (m == NULL) return;
    const char *const *argv;
    CHECK(strcmp(ppc_manifest_name(m), "mqtt") == 0 && ppc_manifest_header_version(m) == 2 && ppc_manifest_command(m, &argv) == 5
          && strcmp(argv[0], "{python}") == 0, "manifest fields");
    CHECK(strcmp(ppc_manifest_dir(m), "/opt/mqtt") == 0 && strcmp(ppc_manifest_source(m), "/opt/mqtt/proxy.toml") == 0, "source and dir");
    const char *const *names, *const *values;
    CHECK(ppc_manifest_environment(m, &names, &values) == 2 && strcmp(names[0], "MQTT_LOG") == 0 && strcmp(values[0], "info") == 0
          && strcmp(values[1], "{manifest_dir}/..:{python}-site") == 0, "environment as written");
    size_t n_env = 0;
    char **resolved = ppc_manifest_resolved_environment(m, "/venv/bin/python", &n_env);
    CHECK(n_env == 2 && resolved && strcmp(resolved[0], "info") == 0 && strcmp(resolved[1], "/opt/mqtt/..:/venv/bin/python-site") == 0,
          "environment placeholders resolved: %s", resolved && n_env == 2 ? resolved[1] : "");
    ppc_strings_free(resolved, n_env);
    size_t argc = 0;
    const char *standard[] = {"--proxy-id", "abc"};
    char **cmd = ppc_manifest_launch_command(m, "/venv/bin/python", standard, 2, &argc);
    CHECK(argc == 7 && strcmp(cmd[0], "/venv/bin/python") == 0 && strcmp(cmd[5], "--proxy-id") == 0 && strcmp(cmd[6], "abc") == 0 && cmd[7] == NULL, "launch command");
    ppc_strings_free(cmd, argc);
    cmd = ppc_manifest_self_test_command(m, NULL, &argc);
    CHECK(argc == 2 && strcmp(cmd[0], "/opt/mqtt/bin/mqtt-proxy") == 0 && strcmp(cmd[1], "--self-test") == 0, "self-test command: %s", cmd ? cmd[0] : "");
    ppc_strings_free(cmd, argc);
    /* Process keys: normalised identity options, defaults for missing ones, Python tuple repr. */
    ppc_option opts[] = {{"host", "  Broker.Example "}, {"username", "u"}};
    const char *remote[] = {"dev-1"};
    ppc_json *key = ppc_manifest_process_key(m, remote, 1, opts, 2);
    char *tuple = ppc_py_tuple(key);
    CHECK(tuple && strcmp(tuple, "('mqtt', 'broker.example', 1883)") == 0, "process key %s", tuple ? tuple : "");
    free(tuple);
    ppc_json_free(key);
    ppc_option other[] = {{"host", "broker.example"}, {"username", "v"}, {"port", "1883"}};
    char *conflicts = ppc_manifest_conflicts(m, opts, 2, other, 3);
    CHECK(conflicts && strcmp(conflicts, "username") == 0, "conflicts: %s", conflicts ? conflicts : "(none)");
    free(conflicts);
    ppc_option same[] = {{"username", "u"}, {"host", "x"}};
    conflicts = ppc_manifest_conflicts(m, opts, 2, same, 2);
    CHECK(conflicts == NULL, "no conflict when must_match agree: %s", conflicts ? conflicts : "");
    free(conflicts);
    ppc_manifest_free(m);
    /* No identity keys: the caller's id as given, as a one-tuple. */
    m = ppc_manifest_parse("[proxy]\nname = \"echo-c\"\ncommand = [\"{manifest_dir}/bin/echo-proxy\"]\n", NULL, err, sizeof err);
    CHECK(m != NULL, "minimal manifest: %s", err);
    const char *conformance[] = {"conformance"};
    key = ppc_manifest_process_key(m, conformance, 1, NULL, 0);
    tuple = ppc_py_tuple(key);
    CHECK(tuple && strcmp(tuple, "('conformance',)") == 0, "one-tuple %s", tuple ? tuple : "");
    free(tuple);
    ppc_json_free(key);
    CHECK(strcmp(ppc_manifest_dir(m), "") == 0 && ppc_manifest_source(m) == NULL, "in-memory manifest has no dir");
    ppc_manifest_free(m);
    /* Validation, as the Python reference refuses. */
    struct { const char *text, *expect; } bad[] = {
        {"[proxy]\nname = \"x\"\ncommand = [\"a\"]\n[extra]\n", "unknown keys [extra]"},
        {"[proxy]\nname = \"x\"\ncommand = [\"{nope}\"]\n", "unknown placeholder {nope}"},
        {"[proxy]\nname = \"x\"\ncommand = [\"a\"]\nheader_version = 3\n", "header_version must be 1 or 2"},
        {"[proxy]\nname = \"x y\"\ncommand = [\"a\"]\n", "name must be a short identifier"},
        {"[proxy]\nname = \"x\"\ncommand = []\n", "non-empty list of strings"},
        {"[identity]\nkeys = [\"a\"]\n", "[proxy] table is required"},
        {"[proxy]\nname = \"x\"\ncommand = [\"a\"]\n[identity]\nkeys = [\"a\"]\n[identity.normalize]\nb = [\"strip\"]\n", "is not in keys or must_match"},
        {"[proxy]\nname = \"x\"\ncommand = [\"a\"]\n[identity]\nkeys = [\"a\"]\n[identity.normalize]\na = [\"upper\"]\n", "unknown normaliser \"upper\""},
        {"[proxy]\nname = \"x\"\ncommand = [\"a\"]\n[environment]\nN = 1\n", "values must be strings"},
        {"[proxy]\nname = \"x\"\ncommand = [\"a\"]\n[environment]\nP = \"{home}/x\"\n", "[environment] P: unknown placeholder {home}"},
        {"[proxy]\nname = \"x\"\ncommand = [\"a\"]\n[self_test]\nrun = [\"a\"]\n", "unknown keys [run]"},
        {"this is not toml\n", "not valid TOML"},
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        m = ppc_manifest_parse(bad[i].text, NULL, err, sizeof err);
        CHECK(m == NULL && strstr(err, bad[i].expect) != NULL, "bad manifest %zu accepted or wrong error: %s", i, err);
        ppc_manifest_free(m);
    }
    /* Discovery: PROTOCOL_PROXY_MANIFESTS first, <name>.toml or <name>/proxy.toml. */
    char dir[] = "/tmp/ppc-manifests-XXXXXX";
    CHECK(mkdtemp(dir) != NULL, "mkdtemp");
    char path[512];
    snprintf(path, sizeof path, "%s/foo.toml", dir);
    FILE *f = fopen(path, "w");
    if (f) { fputs("[proxy]\nname = \"foo\"\ncommand = [\"{manifest_dir}/foo\"]\n", f); fclose(f); }
    snprintf(path, sizeof path, "%s/bar", dir);
    mkdir(path, 0755);
    snprintf(path, sizeof path, "%s/bar/proxy.toml", dir);
    f = fopen(path, "w");
    if (f) { fputs("[proxy]\nname = \"bar\"\ncommand = [\"{manifest_dir}/bar\"]\n", f); fclose(f); }
    setenv("PROTOCOL_PROXY_MANIFESTS", dir, 1);
    size_t n = 0;
    char **dirs = ppc_manifest_search_path(&n);
    CHECK(n >= 4 && strcmp(dirs[0], dir) == 0, "search path starts with PROTOCOL_PROXY_MANIFESTS (%zu entries)", n);
    bool has_etc = false;
    for (size_t i = 0; i < n; i++) if (strcmp(dirs[i], "/etc/protocol-proxy/manifests") == 0) has_etc = true;
    CHECK(has_etc, "search path includes /etc/protocol-proxy/manifests");
    ppc_strings_free(dirs, n);
    char *found = ppc_manifest_locate("foo", err, sizeof err);
    snprintf(path, sizeof path, "%s/foo.toml", dir);
    CHECK(found && strcmp(found, path) == 0, "locate foo: %s", found ? found : err);
    free(found);
    m = ppc_manifest_find("bar", err, sizeof err);
    snprintf(path, sizeof path, "%s/bar", dir);
    CHECK(m && strcmp(ppc_manifest_name(m), "bar") == 0 && strcmp(ppc_manifest_dir(m), path) == 0, "find bar: %s", m ? ppc_manifest_dir(m) : err);
    ppc_manifest_free(m);
    CHECK(ppc_manifest_find("nothing", err, sizeof err) == NULL && strstr(err, "nothing.toml") && strstr(err, "nothing/proxy.toml"), "missing manifest error: %s", err);
    unsetenv("PROTOCOL_PROXY_MANIFESTS");
    snprintf(path, sizeof path, "%s/bar/proxy.toml", dir); unlink(path);
    snprintf(path, sizeof path, "%s/bar", dir); rmdir(path);
    snprintf(path, sizeof path, "%s/foo.toml", dir); unlink(path);
    rmdir(dir);
    CHECK(ppc_option_bool("True", false) && ppc_option_bool(" yes ", false) && !ppc_option_bool("0", true) && ppc_option_bool(NULL, true)
          && ppc_option_bool("maybe", true), "option booleans");
}

/* ---- records (section 9) -------------------------------------------------------------------------------------- */
static void test_records(void) {
    char *name = ppc_proxy_logger_name("echo-c", "('conformance',)");
    CHECK(name && strcmp(name, "protocol_proxy.proxies.echo-c.conformance") == 0, "logger name %s", name ? name : "");
    free(name);
    name = ppc_proxy_logger_name("x", "('mqtt', 'broker.example', 1883)");
    CHECK(name && strcmp(name, "protocol_proxy.proxies.x.mqtt_broker_example_1883") == 0, "logger name %s", name ? name : "");
    free(name);
    name = ppc_proxy_logger_name("x", "(,)");
    CHECK(name && strcmp(name, "protocol_proxy.proxies.x.proxy") == 0, "empty logger name %s", name ? name : "");
    free(name);
    ppc_record r;
    const char *json_line = "{\"name\": \"proxy.mod\", \"levelno\": 20, \"levelname\": \"INFO\", \"msg\": \"hello\", \"process\": 4242}\n";
    CHECK(ppc_record_from_line(json_line, strlen(json_line), "L", "stderr", 7, "P", &r) == 1, "json line");
    CHECK(strcmp(r.logger, "L") == 0 && strcmp(r.remote_name, "proxy.mod") == 0 && strcmp(r.channel, "stderr") == 0 && r.level == 20
          && strcmp(r.msg, "hello") == 0 && r.pid == 4242 && r.fields && strcmp(r.proxy_name, "P") == 0, "json record fields");
    ppc_record_free(&r);
    const char *plain = "Traceback (most recent call last)\r\n";
    CHECK(ppc_record_from_line(plain, strlen(plain), "L", "stderr", 7, "P", &r) == 1 && r.level == PPC_LOG_WARNING
          && strcmp(r.msg, "Traceback (most recent call last)") == 0 && strcmp(r.remote_name, "stderr") == 0 && r.fields == NULL && r.pid == 7,
          "plain stderr line");
    ppc_record_free(&r);
    CHECK(ppc_record_from_line("ready", 5, "L", "stdout", 7, "P", &r) == 1 && r.level == PPC_LOG_INFO, "plain stdout line is INFO");
    ppc_record_free(&r);
    CHECK(ppc_record_from_line("<7>details", 10, "L", "stderr", 7, "P", &r) == 1 && r.level == PPC_LOG_DEBUG && strcmp(r.msg, "details") == 0,
          "syslog prefix");
    ppc_record_free(&r);
    CHECK(ppc_record_from_line("<3>bad", 6, "L", "stdout", 7, "P", &r) == 1 && r.level == PPC_LOG_ERROR, "syslog error prefix");
    ppc_record_free(&r);
    CHECK(ppc_record_from_line("   \n", 4, "L", "stderr", 7, "P", &r) == 0, "empty line");
    const char *no_msg = "{\"name\": \"x\"}";
    CHECK(ppc_record_from_line(no_msg, strlen(no_msg), "L", "stderr", 7, "P", &r) == 1 && r.fields == NULL && strcmp(r.msg, no_msg) == 0,
          "json without msg is a plain line");
    ppc_record_free(&r);
    const char *batch = "{\"records\": [{\"name\": \"a\", \"levelno\": 20, \"msg\": \"one\"}, {\"name\": \"b\", \"levelname\": \"ERROR\", \"msg\": \"two\"}], \"dropped\": 3}";
    ppc_record *records = NULL;
    size_t n = 0;
    CHECK(ppc_records_from_batch(batch, strlen(batch), "L", 9, "P", &records, &n) == PPC_OK && n == 3, "batch: %zu records", n);
    if (n == 3) {
        CHECK(strcmp(records[0].channel, "socket") == 0 && strcmp(records[0].msg, "one") == 0 && records[0].level == 20, "batch record 0");
        CHECK(records[1].level == PPC_LOG_ERROR && strcmp(records[1].remote_name, "b") == 0, "batch record 1 level by name");
        CHECK(records[2].level == PPC_LOG_WARNING && strstr(records[2].msg, "P dropped 3 log records") != NULL, "dropped warning: %s", records[2].msg);
    }
    for (size_t i = 0; i < n; i++) ppc_record_free(&records[i]);
    free(records);
    CHECK(ppc_records_from_batch("nope", 4, "L", 9, "P", &records, &n) == PPC_ERR_INVALID, "bad batch");
    ppc_record_from_line(json_line, strlen(json_line), "L", "stderr", 7, "P", &r);
    ppc_record copy;
    CHECK(ppc_record_copy(&r, &copy) == PPC_OK && strcmp(copy.msg, "hello") == 0 && copy.fields && copy.fields != r.fields, "record copy");
    ppc_record_free(&copy);
    ppc_record_free(&r);
}

/* ---- the certificate authority (section 5) -------------------------------------------------------------------- */
static X509 *parse_cert(const char *pem) {
    BIO *bio = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return x;
}

static bool chains_to(const char *leaf_pem, const char *ca_pem) {
    X509 *leaf = parse_cert(leaf_pem), *ca = parse_cert(ca_pem);
    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, ca);
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, leaf, NULL);
    bool ok = X509_verify_cert(ctx) == 1;
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(leaf);
    X509_free(ca);
    ERR_clear_error();
    return ok;
}

static void test_authority(void) {
    char err[256];
    ppc_authority *a = ppc_authority_new("test CA", err, sizeof err);
    CHECK(a != NULL, "authority: %s", err);
    if (a == NULL) return;
    const char *addresses[] = {"127.0.0.1", "localhost"};
    ppc_tls_material *m = ppc_authority_issue(a, "abc123", addresses, 2, err, sizeof err);
    CHECK(m != NULL, "issue: %s", err);
    if (m == NULL) { ppc_authority_free(a); return; }
    CHECK(strstr(m->ca, "BEGIN CERTIFICATE") && strstr(m->cert, "BEGIN CERTIFICATE") && strstr(m->key, "BEGIN PRIVATE KEY")
          && strcmp(m->ca, ppc_authority_ca_pem(a)) == 0, "PEM material");
    CHECK(chains_to(m->cert, m->ca), "leaf chains to the CA");
    X509 *leaf = parse_cert(m->cert), *ca = parse_cert(m->ca);
    char cn[64] = "";
    X509_NAME_get_text_by_NID(X509_get_subject_name(leaf), NID_commonName, cn, sizeof cn);
    CHECK(strcmp(cn, "abc123") == 0, "leaf CN %s", cn);
    CHECK(X509_check_ca(ca) == 1 && X509_check_ca(leaf) == 0, "CA flags");
    CHECK(X509_check_host(leaf, "abc123", 0, 0, NULL) == 1 && X509_check_host(leaf, "localhost", 0, 0, NULL) == 1
          && X509_check_ip_asc(leaf, "127.0.0.1", 0) == 1 && X509_check_host(leaf, "other", 0, 0, NULL) != 1, "SANs");
    uint32_t eku = X509_get_extended_key_usage(leaf);
    CHECK((eku & XKU_SSL_SERVER) && (eku & XKU_SSL_CLIENT), "EKU server+client");
    BIO *kb = BIO_new_mem_buf(m->key, -1);
    EVP_PKEY *key = PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL);
    BIO_free(kb);
    CHECK(key && X509_check_private_key(leaf, key) == 1, "key matches certificate");
    EVP_PKEY_free(key);
    X509_free(leaf);
    X509_free(ca);
    char *line = ppc_tls_material_line(m);
    ppc_tls_material *back = NULL;
    CHECK(line && line[strlen(line) - 1] == '\n' && ppc_tls_material_parse(line, strlen(line), &back) == PPC_OK && strcmp(back->cert, m->cert) == 0,
          "material line round trip");
    ppc_tls_material_free(back);
    free(line);
    /* A certificate from another authority is refused. */
    ppc_authority *other = ppc_authority_new("other CA", err, sizeof err);
    ppc_tls_material *foreign = ppc_authority_issue(other, "abc123", NULL, 0, err, sizeof err);
    CHECK(foreign && !chains_to(foreign->cert, m->ca), "foreign leaf does not chain");
    /* Two connectors with material from one authority talk TLS; a plain dialler is served only with tls_accept_plain. */
    ppc_uuid id_a, id_b, id_c, tok_a, tok_b, tok_c;
    ppc_uuid_random(&id_a); ppc_uuid_random(&id_b); ppc_uuid_random(&id_c);
    ppc_uuid_random(&tok_a); ppc_uuid_random(&tok_b); ppc_uuid_random(&tok_c);
    char hex_a[33], hex_b[33];
    ppc_uuid_hex(&id_a, hex_a);
    ppc_uuid_hex(&id_b, hex_b);
    ppc_tls_material *mat_a = ppc_authority_issue(a, hex_a, addresses, 1, err, sizeof err);
    ppc_tls_material *mat_b = ppc_authority_issue(a, hex_b, NULL, 0, err, sizeof err);
    ppc_connector_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.proxy_id = id_a; cfg.token = tok_a; cfg.proxy_name = "A-tls"; cfg.inbound_address = "127.0.0.1"; cfg.io_timeout = 5;
    cfg.tls = mat_a; cfg.tls_accept_plain = true; cfg.cipher = "chacha20-poly1305";
    ppc_connector *ca_conn = ppc_connector_new(&cfg);
    cfg.proxy_id = id_b; cfg.token = tok_b; cfg.proxy_name = "B-tls"; cfg.tls = mat_b; cfg.tls_accept_plain = false;
    ppc_connector *cb_conn = ppc_connector_new(&cfg);
    cfg.proxy_id = id_c; cfg.token = tok_c; cfg.proxy_name = "C-plain"; cfg.tls = NULL;
    ppc_connector *cc_conn = ppc_connector_new(&cfg);
    CHECK(ca_conn && cb_conn && cc_conn && ppc_connector_start(ca_conn) == PPC_OK && ppc_connector_start(cb_conn) == PPC_OK
          && ppc_connector_start(cc_conn) == PPC_OK, "TLS connectors");
    char addr_a[64], addr_b[64];
    int port_a = 0, port_b = 0;
    ppc_connector_local_address(ca_conn, addr_a, sizeof addr_a, &port_a);
    ppc_connector_local_address(cb_conn, addr_b, sizeof addr_b, &port_b);
    echo_state st_a = {0}, st_b = {0};
    ppc_connector_register_handler(ca_conn, "ECHO", NULL, echo_handler, &st_a, true);
    ppc_connector_register_handler(cb_conn, "ECHO", NULL, echo_handler, &st_b, true);
    ppc_connector_add_peer(ca_conn, &id_b, &tok_b, addr_b, port_b, NULL, 1, true);
    ppc_peer *a_on_b = ppc_connector_add_peer(cb_conn, &id_a, &tok_a, addr_a, port_a, NULL, 1, true);
    ppc_connector_add_peer(ca_conn, &id_c, &tok_c, NULL, 0, NULL, 0, false);
    ppc_peer *a_on_c = ppc_connector_add_peer(cc_conn, &id_a, &tok_a, addr_a, port_a, NULL, 0, false);
    ppc_peer *b_on_c = ppc_connector_add_peer(cc_conn, &id_b, &tok_b, addr_b, port_b, NULL, 0, false);
    uint8_t *reply = NULL;
    size_t len = 0;
    CHECK(request_text(cb_conn, a_on_b, "ECHO", "over tls", 2, &reply, &len) == PPC_OK && len == 8 && memcmp(reply, "over tls", 8) == 0, "TLS request");
    free(reply);
    CHECK(ppc_peer_linked(a_on_b) && ppc_peer_tls(a_on_b) && !ppc_peer_has_key(a_on_b), "TLS persistent link");
    CHECK(request_text(cc_conn, a_on_c, "ECHO", "plain to a manager", 2, &reply, &len) == PPC_OK && len == 18, "plain request to a tls_accept_plain listener");
    free(reply);
    reply = NULL;
    CHECK(request_text(cc_conn, b_on_c, "ECHO", "plain to a proxy", 2, &reply, &len) != PPC_OK, "plain request to a TLS-only listener refused");
    free(reply);
    ppc_connector_free(cc_conn);
    ppc_connector_free(cb_conn);
    ppc_connector_free(ca_conn);
    ppc_tls_material_free(mat_a);
    ppc_tls_material_free(mat_b);
    ppc_tls_material_free(foreign);
    ppc_authority_free(other);
    ppc_tls_material_free(m);
    ppc_authority_free(a);
}

/* ---- the manager (sections 1, 7, 9, 10, 11b) ------------------------------------------------------------------ */
static double now_mono(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

#define WAIT_FOR(seconds, cond) do { double _deadline = now_mono() + (seconds); while (!(cond) && now_mono() < _deadline) usleep(20000); } while (0)

typedef struct {
    pthread_mutex_t lock;
    ppc_record *items;
    size_t n, cap;
} collector;

static void collect(const ppc_record *r, void *user) {
    collector *c = user;
    pthread_mutex_lock(&c->lock);
    if (c->n == c->cap) {
        size_t cap = c->cap ? c->cap * 2 : 32;
        ppc_record *grown = realloc(c->items, cap * sizeof *grown);
        if (grown) { c->items = grown; c->cap = cap; }
    }
    if (c->n < c->cap && ppc_record_copy(r, &c->items[c->n]) == PPC_OK) c->n++;
    pthread_mutex_unlock(&c->lock);
}

static bool collector_has(collector *c, const char *channel, const char *substring) {
    bool found = false;
    pthread_mutex_lock(&c->lock);
    for (size_t i = 0; i < c->n && !found; i++)
        if ((channel == NULL || strcmp(c->items[i].channel, channel) == 0) && (substring == NULL || strstr(c->items[i].msg, substring))) found = true;
    pthread_mutex_unlock(&c->lock);
    return found;
}

static void collector_free(collector *c) {
    for (size_t i = 0; i < c->n; i++) ppc_record_free(&c->items[i]);
    free(c->items);
    pthread_mutex_destroy(&c->lock);
}

typedef struct {
    pthread_mutex_t lock;
    char reasons[4][128];
    int n;
} lost_log;

static void on_lost(ppc_manager *m, ppc_managed_proxy *p, const char *reason, void *user) {
    (void)m; (void)p;
    lost_log *l = user;
    pthread_mutex_lock(&l->lock);
    if (l->n < 4) snprintf(l->reasons[l->n], sizeof l->reasons[l->n], "%s", reason);
    l->n++;
    pthread_mutex_unlock(&l->lock);
}

static ppc_manifest *echo_manifest(const char *extra) {
    char exe[PATH_MAX];
    if (realpath("bin/echo-proxy", exe) == NULL) return NULL;
    char text[PATH_MAX + 512];
    snprintf(text, sizeof text, "[proxy]\nname = \"echo-test\"\ncommand = [\"%s\"]\n%s", exe, extra ? extra : "");
    char err[256];
    ppc_manifest *m = ppc_manifest_parse(text, NULL, err, sizeof err);
    CHECK(m != NULL, "echo manifest: %s", err);
    return m;
}

static ppc_manager *start_manager(const ppc_manifest *mf, collector *records, bool encrypt, bool tls, const char *cipher,
                                  double heartbeat_interval, double heartbeat_timeout, int misses) {
    ppc_manager_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.manifest = mf;
    cfg.inbound_address = "127.0.0.1";
    cfg.encrypt = encrypt;
    cfg.ipc_tls = tls;
    cfg.cipher = cipher;
    cfg.heartbeat_interval = heartbeat_interval;
    cfg.heartbeat_timeout = heartbeat_timeout;
    cfg.heartbeat_misses = misses;
    cfg.records = records ? collect : NULL;
    cfg.records_user = records;
    char err[512];
    ppc_manager *m = ppc_manager_new(&cfg, err, sizeof err);
    CHECK(m != NULL, "manager: %s", err);
    if (m) CHECK(ppc_manager_start(m) == PPC_OK, "manager start");
    return m;
}

static bool reply_has(ppc_manager *m, ppc_managed_proxy *p, const char *method, const char *payload, const char *key) {
    ppc_message msg = {method, (const uint8_t *)payload, payload ? strlen(payload) : 0, true, NULL, 2, false};
    uint8_t *reply = NULL;
    size_t len = 0;
    int rc = ppc_manager_request(m, p, &msg, 5.0, &reply, &len);
    bool ok = false;
    if (rc == PPC_OK && reply) {
        char err[64];
        ppc_json *v = ppc_json_parse((const char *)reply, len, err, sizeof err);
        ok = v && ppc_json_get(v, key) != NULL;
        ppc_json_free(v);
    }
    free(reply);
    return ok;
}

static bool echo_round_trip(ppc_manager *m, ppc_managed_proxy *p, size_t size) {
    char *payload = malloc(size + 16);
    snprintf(payload, size + 16, "{\"blob\": \"");
    size_t head = strlen(payload);
    memset(payload + head, 'x', size);
    memcpy(payload + head + size, "\"}", 3);
    size_t len = head + size + 2;
    ppc_message msg = {"ECHO", (const uint8_t *)payload, len, true, NULL, 2, false};
    uint8_t *reply = NULL;
    size_t reply_len = 0;
    int rc = ppc_manager_request(m, p, &msg, 10.0, &reply, &reply_len);
    bool ok = rc == PPC_OK && reply_len == len && memcmp(reply, payload, len) == 0;
    free(reply);
    free(payload);
    return ok;
}

static bool command_has(ppc_managed_proxy *p, const char *flag, const char *value) {
    const char *const *argv;
    size_t argc = ppc_managed_proxy_command(p, &argv);
    for (size_t i = 0; i + 1 < argc; i++) if (strcmp(argv[i], flag) == 0 && strcmp(argv[i + 1], value) == 0) return true;
    return false;
}

static void test_manager_launches_talks_and_logs(ppc_manifest *mf) {
    collector records = {PTHREAD_MUTEX_INITIALIZER, NULL, 0, 0};
    ppc_manager *m = start_manager(mf, &records, false, false, NULL, 0.2, 1.0, 0);
    if (m == NULL) return;
    char err[256];
    const char *remote[] = {"device"};
    ppc_option opts[] = {{"persistent", "true"}};
    ppc_managed_proxy *p = ppc_manager_get_proxy(m, remote, 1, opts, 1, err, sizeof err);
    CHECK(p != NULL, "get_proxy: %s", err);
    if (p == NULL) { ppc_manager_free(m); collector_free(&records); return; }
    CHECK(strcmp(ppc_managed_proxy_state(p), "launching") == 0 && strcmp(ppc_managed_proxy_name(p), "('device',)") == 0, "initial state and name");
    CHECK(ppc_manager_wait_registered(m, p, 10.0) == PPC_OK, "registration");
    CHECK(ppc_managed_proxy_registered(p) && ppc_managed_proxy_pid(p) > 0 && ppc_managed_proxy_running(p), "registered and running");
    CHECK(ppc_manager_get_proxy(m, remote, 1, opts, 1, err, sizeof err) == p, "same key, same proxy");
    CHECK(reply_has(m, p, "PING", NULL, "uptime"), "PING");
    CHECK(echo_round_trip(m, p, 70000), "ECHO 70 KB (compressed on the wire)");
    uint8_t *reply = NULL;
    size_t len = 0;
    CHECK(ppc_manager_set_proxy_log_level(m, p, PPC_LOG_DEBUG, 5.0, &reply, &len) == PPC_OK && reply && strstr((char *)reply, "DEBUG")
          && ppc_managed_proxy_log_level(p) == PPC_LOG_DEBUG, "SET_LOG_LEVEL: %.*s", (int)len, reply ? (char *)reply : "");
    free(reply);
    WAIT_FOR(5.0, collector_has(&records, "socket", "logging over the IPC socket"));
    CHECK(collector_has(&records, "socket", "logging over the IPC socket"), "the switch record arrived in a LOG batch");
    CHECK(collector_has(&records, "stderr", "Registered with manager"), "records before registration came by stderr");
    WAIT_FOR(5.0, collector_has(&records, "socket", "log level set to DEBUG"));
    CHECK(collector_has(&records, "socket", "log level set to DEBUG"), "SET_LOG_LEVEL confirmation over the socket");
    WAIT_FOR(5.0, strcmp(ppc_managed_proxy_state(p), "healthy") == 0);
    CHECK(strcmp(ppc_managed_proxy_state(p), "healthy") == 0, "heartbeat answered: state %s", ppc_managed_proxy_state(p));
    char *health = ppc_manager_health_json(m);
    CHECK(health && strstr(health, "\"('device',)\"") && strstr(health, "\"state\": \"healthy\"") && strstr(health, "\"uptime\""), "health: %s", health ? health : "");
    free(health);
    size_t n = 0;
    ppc_managed_proxy **list = ppc_manager_proxies(m, &n);
    CHECK(n == 1 && list[0] == p && ppc_manager_proxy_by_id(m, ppc_managed_proxy_id(p)) == p, "proxy listing");
    free(list);
    ppc_manager_stop(m, true, 5.0);
    int code = -99;
    CHECK(ppc_managed_proxy_wait(p, 10.0, &code) && code == 0, "clean exit on stop: code %d", code);
    WAIT_FOR(3.0, collector_has(&records, "stderr", "; stopping."));
    CHECK(collector_has(&records, "stderr", "; stopping."), "the exit drain reached stderr");
    ppc_manager_free(m);
    collector_free(&records);
}

static void test_manager_relaunches_after_exit(ppc_manifest *mf) {
    ppc_manager *m = start_manager(mf, NULL, false, false, NULL, -1, 0, 0);
    if (m == NULL) return;
    lost_log lost = {PTHREAD_MUTEX_INITIALIZER, {{0}}, 0};
    ppc_manager_on_proxy_lost(m, on_lost, &lost);
    char err[256];
    const char *remote[] = {"d"};
    ppc_managed_proxy *p = ppc_manager_get_proxy(m, remote, 1, NULL, 0, err, sizeof err);
    CHECK(p && ppc_manager_wait_registered(m, p, 10.0) == PPC_OK, "first launch: %s", err);
    if (p == NULL) { ppc_manager_free(m); return; }
    pid_t first = ppc_managed_proxy_pid(p);
    kill(first, SIGKILL);
    WAIT_FOR(5.0, lost.n >= 1);
    CHECK(lost.n == 1 && strcmp(lost.reasons[0], "process exited with code -9") == 0, "lost callback: %d, %s", lost.n, lost.reasons[0]);
    CHECK(ppc_manager_proxy_by_id(m, ppc_managed_proxy_id(p)) == NULL && ppc_managed_proxy_lost(p) && ppc_managed_proxy_lost_reason(p), "forgotten");
    ppc_managed_proxy *again = ppc_manager_get_proxy(m, remote, 1, NULL, 0, err, sizeof err);
    CHECK(again && again != p && ppc_uuid_equal(ppc_managed_proxy_id(again), ppc_managed_proxy_id(p)), "relaunch: new proxy, same id (%s)", err);
    CHECK(again && ppc_manager_wait_registered(m, again, 10.0) == PPC_OK && ppc_managed_proxy_pid(again) != first, "relaunched proxy registers under a new pid");
    ppc_manager_free(m);
}

static void test_manager_loses_an_unresponsive_proxy(ppc_manifest *mf) {
    ppc_manager *m = start_manager(mf, NULL, false, false, NULL, 0.1, 0.3, 2);
    if (m == NULL) return;
    lost_log lost = {PTHREAD_MUTEX_INITIALIZER, {{0}}, 0};
    ppc_manager_on_proxy_lost(m, on_lost, &lost);
    char err[256];
    const char *remote[] = {"d"};
    ppc_option opts[] = {{"persistent", "true"}};
    ppc_managed_proxy *p = ppc_manager_get_proxy(m, remote, 1, opts, 1, err, sizeof err);
    CHECK(p && ppc_manager_wait_registered(m, p, 10.0) == PPC_OK, "launch: %s", err);
    if (p == NULL) { ppc_manager_free(m); return; }
    WAIT_FOR(5.0, strcmp(ppc_managed_proxy_state(p), "healthy") == 0);
    kill(ppc_managed_proxy_pid(p), SIGSTOP);
    WAIT_FOR(10.0, lost.n >= 1);
    CHECK(lost.n == 1 && strcmp(lost.reasons[0], "missed 2 heartbeats") == 0, "lost after misses: %d, %s", lost.n, lost.reasons[0]);
    kill(ppc_managed_proxy_pid(p), SIGCONT);
    CHECK(ppc_managed_proxy_wait(p, 10.0, NULL), "the lost proxy's process was terminated");
    ppc_manager_free(m);
}

static void test_manager_encryption_tls_and_plain(ppc_manifest *mf) {
    ppc_manager *m = start_manager(mf, NULL, true, true, "chacha20-poly1305", -1, 0, 0);
    if (m == NULL) return;
    char err[256];
    const char *secure_id[] = {"secure"}, *plain_id[] = {"plain"};
    ppc_option secure_opts[] = {{"persistent", "true"}};
    ppc_option plain_opts[] = {{"persistent", "false"}, {"ipc_tls", "false"}, {"encrypt", "false"}};
    ppc_managed_proxy *secure = ppc_manager_get_proxy(m, secure_id, 1, secure_opts, 1, err, sizeof err);
    CHECK(secure != NULL, "secure launch: %s", err);
    ppc_managed_proxy *plain = ppc_manager_get_proxy(m, plain_id, 1, plain_opts, 3, err, sizeof err);
    CHECK(plain != NULL, "plain launch: %s", err);
    if (secure == NULL || plain == NULL) { ppc_manager_free(m); return; }
    CHECK(ppc_manager_wait_registered(m, secure, 10.0) == PPC_OK && ppc_manager_wait_registered(m, plain, 10.0) == PPC_OK, "both register");
    CHECK(ppc_peer_tls(ppc_managed_proxy_peer(secure)) && ppc_peer_has_key(ppc_managed_proxy_peer(secure))
          && ppc_managed_proxy_cipher(secure) && strcmp(ppc_managed_proxy_cipher(secure), "chacha20-poly1305") == 0, "secure peer flags");
    CHECK(!ppc_peer_tls(ppc_managed_proxy_peer(plain)) && !ppc_peer_has_key(ppc_managed_proxy_peer(plain)), "plain peer flags");
    CHECK(echo_round_trip(m, secure, 70000) && echo_round_trip(m, plain, 70000), "ECHO through both");
    CHECK(command_has(secure, "--ipc-tls", "true") && command_has(secure, "--encrypt", "true") && command_has(secure, "--cipher", "chacha20-poly1305")
          && command_has(secure, "--log-level", "INFO") && command_has(secure, "--persistent", "true"), "secure launch command");
    CHECK(command_has(plain, "--ipc-tls", "false") && command_has(plain, "--encrypt", "false") && !command_has(plain, "--cipher", "chacha20-poly1305"), "plain launch command");
    ppc_manager_free(m);
}

static int pick_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t sl = sizeof sa;
    int port = 0;
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0 && getsockname(fd, (struct sockaddr *)&sa, &sl) == 0) port = ntohs(sa.sin_port);
    close(fd);
    return port;
}

static void test_manager_dials(ppc_manifest *mf) {
    ppc_manager *m = start_manager(mf, NULL, false, false, NULL, -1, 0, 0);
    if (m == NULL) return;
    char err[256], port_text[16];
    snprintf(port_text, sizeof port_text, "%d", pick_port());
    const char *remote[] = {"remote"};
    ppc_option opts[] = {{"manager_dials", "true"}, {"inbound_address", "127.0.0.1"}, {"inbound_port", port_text}};
    ppc_managed_proxy *p = ppc_manager_get_proxy(m, remote, 1, opts, 3, err, sizeof err);
    CHECK(p && ppc_manager_wait_registered(m, p, 10.0) == PPC_OK, "manager-dials launch: %s", err);
    if (p) {
        CHECK(ppc_peer_linked(ppc_managed_proxy_peer(p)) && ppc_peer_persistent(ppc_managed_proxy_peer(p), ppc_manager_connector(m)), "dialled persistent link");
        CHECK(reply_has(m, p, "PING", NULL, "uptime"), "PING over the dialled connection");
    }
    const char *nowhere[] = {"nowhere"};
    ppc_option bad[] = {{"manager_dials", "true"}};
    CHECK(ppc_manager_get_proxy(m, nowhere, 1, bad, 1, err, sizeof err) == NULL && strstr(err, "inbound_port"), "manager_dials without a port refused: %s", err);
    ppc_manager_free(m);
}

static void test_manager_keys_and_conflicts(void) {
    ppc_manifest *mf = echo_manifest("[identity]\nkeys = [\"host\"]\nmust_match = [\"username\"]\n[identity.normalize]\nhost = [\"strip\", \"lowercase\"]\n");
    if (mf == NULL) return;
    ppc_manager *m = start_manager(mf, NULL, false, false, NULL, -1, 0, 0);
    if (m == NULL) { ppc_manifest_free(mf); return; }
    char err[256];
    const char *a_id[] = {"a"}, *b_id[] = {"b"}, *c_id[] = {"c"};
    ppc_option a_opts[] = {{"host", " Broker "}, {"username", "u"}};
    ppc_option b_opts[] = {{"host", "broker"}, {"username", "u"}};
    ppc_option c_opts[] = {{"host", "broker"}, {"username", "v"}};
    ppc_managed_proxy *a = ppc_manager_get_proxy(m, a_id, 1, a_opts, 2, err, sizeof err);
    CHECK(a != NULL, "a: %s", err);
    ppc_managed_proxy *b = ppc_manager_get_proxy(m, b_id, 1, b_opts, 2, err, sizeof err);
    CHECK(b == a, "two remotes of one broker share a process: %s", err);
    CHECK(a && strcmp(ppc_managed_proxy_name(a), "('echo-test', 'broker')") == 0, "process key %s", a ? ppc_managed_proxy_name(a) : "");
    CHECK(ppc_manager_get_proxy(m, c_id, 1, c_opts, 2, err, sizeof err) == NULL && strstr(err, "differs in username"), "conflict refused: %s", err);
    CHECK(a && command_has(a, "--host", " Broker ") && command_has(a, "--username", "u"), "protocol options passed as given");
    CHECK(a && ppc_manager_wait_registered(m, a, 10.0) == PPC_OK, "shared process registers");
    ppc_manager_free(m);
    ppc_manifest_free(mf);
}

static void test_manager_gives_up_and_launch_failures(void) {
    char err[256];
    ppc_manifest *sleeper = ppc_manifest_parse("[proxy]\nname = \"sleeper\"\ncommand = [\"/bin/sh\", \"-c\", \"exec sleep 30\", \"sh\"]\n", NULL, err, sizeof err);
    ppc_manager *m = start_manager(sleeper, NULL, false, false, NULL, -1, 0, 0);
    if (m) {
        lost_log lost = {PTHREAD_MUTEX_INITIALIZER, {{0}}, 0};
        ppc_manager_on_proxy_lost(m, on_lost, &lost);
        const char *remote[] = {"s"};
        ppc_managed_proxy *p = ppc_manager_get_proxy(m, remote, 1, NULL, 0, err, sizeof err);
        CHECK(p != NULL, "sleeper launch: %s", err);
        if (p) {
            CHECK(ppc_manager_wait_registered(m, p, 0.5) == PPC_ERR_TIMEOUT, "registration wait times out");
            CHECK(lost.n == 1 && strcmp(lost.reasons[0], "did not register within 0.5 seconds") == 0, "lost: %s", lost.reasons[0]);
            int code = 0;
            CHECK(ppc_managed_proxy_wait(p, 10.0, &code) && code == -15, "terminated with SIGTERM: code %d", code);
            CHECK(ppc_manager_proxy_by_id(m, ppc_managed_proxy_id(p)) == NULL, "forgotten after the timeout");
        }
        ppc_manager_free(m);
    }
    ppc_manifest_free(sleeper);
    ppc_manifest *missing = ppc_manifest_parse("[proxy]\nname = \"missing\"\ncommand = [\"/nonexistent/protocol-proxy-binary\"]\n", NULL, err, sizeof err);
    m = start_manager(missing, NULL, false, false, NULL, -1, 0, 0);
    if (m) {
        const char *remote[] = {"x"};
        CHECK(ppc_manager_get_proxy(m, remote, 1, NULL, 0, err, sizeof err) == NULL && strstr(err, "unable to launch"), "launch failure: %s", err);
        size_t n = 1;
        ppc_managed_proxy **list = ppc_manager_proxies(m, &n);
        CHECK(n == 0, "a failed launch leaves no proxy");
        free(list);
        ppc_manager_free(m);
    }
    ppc_manifest_free(missing);
    /* A manager with its own self test (section 1a). */
    ppc_manifest *tested = ppc_manifest_parse("[proxy]\nname = \"t\"\ncommand = [\"/bin/true\"]\n[self_test]\ncommand = [\"/bin/sh\", \"-c\", \"echo fine\"]\n", NULL, err, sizeof err);
    m = start_manager(tested, NULL, false, false, NULL, -1, 0, 0);
    if (m) { CHECK(ppc_manager_self_test(m, err, sizeof err) == PPC_OK, "self test passes: %s", err); ppc_manager_free(m); }
    ppc_manifest_free(tested);
    tested = ppc_manifest_parse("[proxy]\nname = \"t\"\ncommand = [\"/bin/true\"]\n[self_test]\ncommand = [\"/bin/sh\", \"-c\", \"echo broken; exit 3\"]\n", NULL, err, sizeof err);
    m = start_manager(tested, NULL, false, false, NULL, -1, 0, 0);
    if (m) { CHECK(ppc_manager_self_test(m, err, sizeof err) == PPC_ERR_IO && strstr(err, "status 3") && strstr(err, "broken"), "self test failure reported: %s", err); ppc_manager_free(m); }
    ppc_manifest_free(tested);
}

static void test_conformance_harness(ppc_manifest *mf) {
    ppc_conformance_options opts;
    memset(&opts, 0, sizeof opts);
    opts.echo_method = "ECHO";
    opts.tls = true;
    opts.manager_dials = true;
    ppc_conformance_report *report = ppc_conformance_run(mf, &opts);
    CHECK(report != NULL, "conformance run");
    if (report == NULL) return;
    char *text = ppc_conformance_text(report);
    int skipped = 0;
    for (size_t i = 0; i < report->n_checks; i++) if (report->checks[i].skipped) skipped++;
    CHECK(ppc_conformance_ok(report) && report->n_checks == 26 && skipped == 0, "26 checks, none skipped:\n%s", text ? text : "");
    CHECK(report->n_features >= 5 && text && strstr(text, "all checks pass (26 passed, 0 failed, 0 skipped)"), "report header: %s", text ? text : "");
    free(text);
    char *json = ppc_conformance_json(report);
    CHECK(json && strstr(json, "\"ok\": true") && strstr(json, "\"status\": \"pass\""), "json report");
    free(json);
    ppc_conformance_report_free(report);
}

static void test_manager(void) {
    ppc_manifest *mf = echo_manifest(NULL);
    if (mf == NULL) { fprintf(stderr, "bin/echo-proxy not built: manager tests skipped\n"); return; }
    test_manager_launches_talks_and_logs(mf);
    test_manager_relaunches_after_exit(mf);
    test_manager_loses_an_unresponsive_proxy(mf);
    test_manager_encryption_tls_and_plain(mf);
    test_manager_dials(mf);
    test_manager_keys_and_conflicts();
    test_manager_gives_up_and_launch_failures();
    test_conformance_harness(mf);
    ppc_manifest_free(mf);
}

static int main_vectors(const char *path) {
    int failures_in_vectors = ppc_selftest_vectors(path, stderr);
    CHECK(failures_in_vectors == 0, "vectors: %d failure(s)", failures_in_vectors);
    return failures_in_vectors;
}

int main(int argc, char **argv) {
    ppc_log_init("WARNING", 0, "test");
    const char *vectors = argc > 1 ? argv[1] : "tests/test_vectors.json";
    main_vectors(vectors);
    test_json();
    test_log_queue();
    test_codecs();
    test_headers();
    test_options();
    test_loopback(false, false);
    test_loopback(true, false);
    test_loopback(false, true);
    test_loopback(true, true);
    test_heap_growth();
    test_manifest();
    test_records();
    test_authority();
    test_manager();
    fprintf(stderr, "%d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
