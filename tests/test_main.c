/* Unit tests: headers against the vectors, JSON, compression, AEAD, option parsing, the stdin handshake, and
 * loopback request/response between two connectors in one process (per-message, persistent, adoption, errors,
 * encryption, compression, the large-frame rule). Run by `make test` under the sanitizers. */
#include "ppc/ppc.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

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
    ppc_message m = {method, (const uint8_t *)text, strlen(text), true, NULL, version};
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
    ppc_message push = {"SILENT", (const uint8_t *)"{}", 2, false, NULL, 2};
    CHECK(ppc_connector_send(b, a_on_b, &push) == PPC_OK, "%s: push", mode);
    for (int i = 0; i < 100 && silent_calls < 2; i++) usleep(10000);
    CHECK(silent_calls == 2, "%s: push delivered (%d)", mode, silent_calls);
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
    test_codecs();
    test_headers();
    test_options();
    test_loopback(false, false);
    test_loopback(true, false);
    test_loopback(false, true);
    test_loopback(true, true);
    fprintf(stderr, "%d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
