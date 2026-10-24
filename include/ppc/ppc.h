/* protocol-proxy C port: public API.
 *
 * Implements the wire contract of PROTOCOL.md (the protocol-proxy repository): frames with version 1 and 2
 * headers, per-message and persistent TCP connections in both directions, authentication by sender id and token,
 * zlib compression, ChaCha20-Poly1305 / AES-256-GCM AEAD, registration, the core methods, JSON log records on
 * stderr, and the proxy process lifecycle (command line, stdin handshake, parent watch, SIGTERM).
 *
 * Everything is C11 + POSIX (Linux). Dependencies: zlib, OpenSSL libcrypto (and libssl for the optional TLS).
 */
#ifndef PPC_H
#define PPC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- errors --------------------------------------------------------------------------------------------------- */
enum {
    PPC_OK = 0,
    PPC_ERR_INVALID = -1,       /* bad argument or malformed data */
    PPC_ERR_NOMEM = -2,
    PPC_ERR_IO = -3,            /* socket or file error (errno may say more) */
    PPC_ERR_TIMEOUT = -4,
    PPC_ERR_CONNECTION = -5,    /* connection lost or refused */
    PPC_ERR_NO_ROUTE = -6,      /* no open connection and no address to dial */
    PPC_ERR_AUTH = -7,          /* frame refused: unknown sender, bad token, wrong encryption mode, bad tag */
    PPC_ERR_STOPPED = -8,       /* the connector is stopping */
    PPC_ERR_PROTOCOL = -9,      /* unknown header version or oversized frame */
    PPC_ERR_TLS = -10,
};

const char *ppc_strerror(int code);

/* ---- UUIDs ---------------------------------------------------------------------------------------------------- */
typedef struct { uint8_t b[16]; } ppc_uuid;

/* Parse 32 hex digits, optionally with the usual dashes. Returns PPC_OK or PPC_ERR_INVALID. */
int ppc_uuid_parse(const char *text, ppc_uuid *out);
/* 32 lower-case hex digits, NUL-terminated (buffer of at least 33). */
void ppc_uuid_hex(const ppc_uuid *id, char out[33]);
/* 8-4-4-4-12 form, NUL-terminated (buffer of at least 37). */
void ppc_uuid_str(const ppc_uuid *id, char out[37]);
bool ppc_uuid_equal(const ppc_uuid *a, const ppc_uuid *b);
bool ppc_uuid_is_nil(const ppc_uuid *id);
int ppc_uuid_random(ppc_uuid *out);

/* ---- headers (PROTOCOL.md section 3) -------------------------------------------------------------------------- */
#define PPC_METHOD_MAX 32
#define PPC_HEADER_V1_LENGTH 76      /* bytes after the version word */
#define PPC_HEADER_V2_LENGTH 94
#define PPC_FRAME_HEADER_MAX (2 + PPC_HEADER_V2_LENGTH)
#define PPC_REQUEST_ID_MAX_V1 0xFFFFu
#define PPC_REQUEST_ID_MAX_V2 0xFFFFFFFFu

enum {
    PPC_BIT_RESPONSE_EXPECTED = 0,
    PPC_BIT_COMPRESSED = 1,
    PPC_BIT_ENCRYPTED = 2,
    PPC_BIT_KEEP_ALIVE = 3,
    PPC_BIT_AES_GCM = 4,
};
#define PPC_FLAG(bit) ((uint16_t)(1u << (bit)))

typedef struct {
    uint16_t version;                   /* 1 or 2 */
    uint64_t data_length;               /* payload bytes on the wire */
    char method_name[PPC_METHOD_MAX + 1];
    uint32_t request_id;
    ppc_uuid sender_id;
    ppc_uuid sender_token;
    uint16_t bitflags;
    ppc_uuid remote_id;                 /* version 2 only; all zeros when absent */
} ppc_header;

/* Whole header length including the version word for a version, 0 for an unknown version. */
size_t ppc_header_length(uint16_t version);
/* Pack into out (at least PPC_FRAME_HEADER_MAX bytes); *out_len receives the length written. */
int ppc_header_pack(const ppc_header *h, uint8_t *out, size_t *out_len);
/* Unpack a whole header (version word included). len must be at least ppc_header_length(version). */
int ppc_header_unpack(const uint8_t *buf, size_t len, ppc_header *out);
static inline bool ppc_header_flag(const ppc_header *h, int bit) { return (h->bitflags >> bit) & 1u; }

/* ---- JSON ------------------------------------------------------------------------------------------------------ */
typedef enum { PPC_JSON_NULL, PPC_JSON_BOOL, PPC_JSON_NUMBER, PPC_JSON_STRING, PPC_JSON_ARRAY, PPC_JSON_OBJECT } ppc_json_type;

typedef struct ppc_json ppc_json;
struct ppc_json {
    ppc_json_type type;
    bool boolean;
    double number;
    bool is_integer;                    /* number was written without fraction or exponent and fits long long */
    long long integer;
    char *string;                       /* UTF-8, NUL-terminated */
    ppc_json **items;                   /* array elements or object values */
    char **keys;                        /* object keys (parallel to items) */
    size_t count;
};

ppc_json *ppc_json_parse(const char *text, size_t len, char *err, size_t err_len);
void ppc_json_free(ppc_json *v);
const ppc_json *ppc_json_get(const ppc_json *object, const char *key);
/* Convenience accessors; return the default when the key is missing or of another type. */
const char *ppc_json_get_string(const ppc_json *object, const char *key, const char *dflt);
bool ppc_json_get_bool(const ppc_json *object, const char *key, bool dflt);
double ppc_json_get_number(const ppc_json *object, const char *key, double dflt);

ppc_json *ppc_json_new_null(void);
ppc_json *ppc_json_new_bool(bool v);
ppc_json *ppc_json_new_number(double v);
ppc_json *ppc_json_new_integer(long long v);
ppc_json *ppc_json_new_string(const char *s);
ppc_json *ppc_json_new_array(void);
ppc_json *ppc_json_new_object(void);
/* Both take ownership of value (and set/append nothing if value is NULL, returning PPC_ERR_NOMEM). */
int ppc_json_object_set(ppc_json *object, const char *key, ppc_json *value);
int ppc_json_array_append(ppc_json *array, ppc_json *value);
/* Python json.dumps formatting (", " and ": " separators, non-ASCII escaped). malloc'd; caller frees. */
char *ppc_json_dump(const ppc_json *v);

/* ---- payload codecs (sections 4 and 5) ------------------------------------------------------------------------ */
#define PPC_KEY_BYTES 32
#define PPC_NONCE_BYTES 12
#define PPC_TAG_BYTES 16

int ppc_zlib_compress(const uint8_t *in, size_t len, uint8_t **out, size_t *out_len);
/* max_out bounds the decompressed size (0: default 256 MiB). */
int ppc_zlib_decompress(const uint8_t *in, size_t len, uint8_t **out, size_t *out_len, size_t max_out);
/* out holds plain_len + PPC_TAG_BYTES bytes: ciphertext then tag. */
int ppc_aead_seal(bool aes_gcm, const uint8_t key[PPC_KEY_BYTES], const uint8_t nonce[PPC_NONCE_BYTES],
                  const uint8_t *aad, size_t aad_len, const uint8_t *plain, size_t plain_len, uint8_t *out);
/* in is ciphertext then tag (len >= PPC_TAG_BYTES); out holds len - PPC_TAG_BYTES bytes. PPC_ERR_AUTH on a bad tag. */
int ppc_aead_open(bool aes_gcm, const uint8_t key[PPC_KEY_BYTES], const uint8_t nonce[PPC_NONCE_BYTES],
                  const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out);
int ppc_random_bytes(uint8_t *out, size_t len);
bool ppc_cpu_has_aes(void);
/* "auto" (or NULL) -> "aes-256-gcm" when the CPU has AES instructions else "chacha20-poly1305"; a known name as given;
 * NULL for an unknown name. */
const char *ppc_resolve_cipher(const char *cipher);
/* The feature a peer must advertise for a cipher name, and whether the AES-GCM bit is set with it. */
const char *ppc_cipher_feature(const char *cipher);
bool ppc_cipher_is_aes_gcm(const char *cipher);
#define PPC_BASELINE_CIPHER "chacha20-poly1305"

/* ---- logging (section 9) -------------------------------------------------------------------------------------- */
enum { PPC_LOG_DEBUG = 10, PPC_LOG_INFO = 20, PPC_LOG_WARNING = 30, PPC_LOG_ERROR = 40, PPC_LOG_CRITICAL = 50 };

/* json_lines: 1 JSON records, 0 readable text, -1 auto (JSON when _LAUNCHED_BY_PROXY_MANAGER is set and stderr is a
 * pipe). level_name may be NULL (PROTOCOL_PROXY_LOG_LEVEL or INFO). process_name labels the records. */
void ppc_log_init(const char *level_name, int json_lines, const char *process_name);
int ppc_log_level(void);
void ppc_log_set_level(int level);
/* A level name ("DEBUG", "warning", "WARN", "FATAL", "20") to its number, or -1. */
int ppc_log_level_from_name(const char *name);
const char *ppc_log_level_name(int level);
void ppc_log(int level, const char *logger, const char *file, int line, const char *func, const char *fmt, ...)
    __attribute__((format(printf, 6, 7)));
#define PPC_LOG_AT(level, logger, ...) ppc_log((level), (logger), __FILE__, __LINE__, __func__, __VA_ARGS__)
/* Render one record as the JSON line the manager reads (for tests and LOG batches). malloc'd. */
char *ppc_log_record_json(int level, const char *logger, const char *file, int line, const char *func, const char *msg);

/* ---- TLS material (section 5, optional) ----------------------------------------------------------------------- */
typedef struct {
    char *ca;       /* PEM */
    char *cert;     /* PEM */
    char *key;      /* PEM */
} ppc_tls_material;

/* Parse the {"ca", "cert", "key"} JSON line the manager writes to stdin. */
int ppc_tls_material_parse(const char *line, size_t len, ppc_tls_material **out);
void ppc_tls_material_free(ppc_tls_material *m);

/* ---- connector (sections 2, 3, 6) ----------------------------------------------------------------------------- */
typedef struct ppc_connector ppc_connector;
typedef struct ppc_peer ppc_peer;

typedef struct {
    ppc_uuid proxy_id;
    ppc_uuid token;
    const char *proxy_name;             /* for log lines; NULL: the id */
    const char *inbound_address;        /* NULL: "localhost" */
    int inbound_port;                   /* 0: first free port in min_port..max_port */
    int min_port, max_port;             /* 0: 22801..22899 */
    bool persistent;                    /* default connection policy toward peers without their own */
    size_t persistent_max_frame;        /* frames above this take their own connection (0: default 256 KiB) */
    long compress_threshold;            /* payloads above this are compressed toward peers that take it; -1 never;
                                           0: default 4096 (use PPC_COMPRESS_EVERYTHING to compress every byte) */
    const char *cipher;                 /* "auto", "aes-256-gcm", "chacha20-poly1305"; NULL: auto */
    double io_timeout;                  /* seconds for a dial or a per-message exchange (0: 30) */
    size_t max_frame;                   /* frames with a larger data_length are refused (0: 256 MiB) */
    ppc_tls_material *tls;              /* this end's TLS identity (NULL: no TLS) */
    bool tls_accept_plain;              /* with tls: also accept plain connections (a manager does; a proxy must not) */
} ppc_connector_config;
#define PPC_COMPRESS_EVERYTHING (-2L)
#define PPC_DEFAULT_COMPRESS_THRESHOLD 4096L
#define PPC_DEFAULT_PERSISTENT_MAX_FRAME (256u * 1024u)

/* A handler receives the decoded payload and, if it provides a response, sets *reply (malloc'd, may stay NULL for
 * an empty reply) and *reply_len. Return PPC_OK, or a negative code to send an error reply instead. Handlers run on
 * the connection's reader thread. */
typedef int (*ppc_handler_fn)(ppc_connector *c, const ppc_header *h, const uint8_t *payload, size_t len,
                              uint8_t **reply, size_t *reply_len, void *user);

typedef struct {
    const char *method_name;
    const uint8_t *payload;
    size_t payload_len;
    bool response_expected;
    const ppc_uuid *remote_id;          /* NULL: none */
    int protocol_version;               /* 0 or 2: version 2; 1: version 1 */
} ppc_message;

ppc_connector *ppc_connector_new(const ppc_connector_config *config);
/* Bind the listener and start accepting. */
int ppc_connector_start(ppc_connector *c);
/* Stop accepting, close every connection, fail pending requests and join every thread. Idempotent. */
void ppc_connector_stop(ppc_connector *c);
void ppc_connector_free(ppc_connector *c);
bool ppc_connector_stopping(const ppc_connector *c);
/* Where this connector listens (valid after start). */
int ppc_connector_local_address(ppc_connector *c, char *address, size_t address_len, int *port);
const ppc_uuid *ppc_connector_id(const ppc_connector *c);
const char *ppc_connector_name(const ppc_connector *c);
const char *ppc_connector_cipher(const ppc_connector *c);
/* time() of the last frame received, 0 if none. */
double ppc_connector_last_activity(const ppc_connector *c);
/* Number of distinct remote ids with their own handlers. */
size_t ppc_connector_remote_count(const ppc_connector *c);

/* Peers: address may be NULL and port 0 for a peer reached only over a connection it opens; key (32 bytes) NULL for
 * clear text; persistent -1 for the connector's default; tls whether connections with it are TLS. */
ppc_peer *ppc_connector_add_peer(ppc_connector *c, const ppc_uuid *id, const ppc_uuid *token, const char *address,
                                 int port, const uint8_t *key, int persistent, bool tls);
ppc_peer *ppc_connector_find_peer(ppc_connector *c, const ppc_uuid *id);
void ppc_peer_set_features(ppc_peer *p, const char *const *features, size_t count);
bool ppc_peer_has_feature(ppc_peer *p, const char *feature);
size_t ppc_peer_feature_count(ppc_peer *p);
/* Whether the peer has a live persistent connection (dialled by us or adopted). */
bool ppc_peer_linked(ppc_peer *p);
const ppc_uuid *ppc_peer_id(const ppc_peer *p);

/* Handlers are keyed by (method, remote_id) first and method second. Registering the same method without a remote
 * twice keeps the first (as the Python connectors do); with a remote the last registration wins. */
int ppc_connector_register_handler(ppc_connector *c, const char *method_name, const ppc_uuid *remote_id,
                                   ppc_handler_fn fn, void *user, bool provides_response);

/* Send a message. With response_expected, wait up to timeout seconds and return the reply payload in *reply
 * (malloc'd; may be NULL with *reply_len 0 for an empty reply). Without, return once the frame is written. */
int ppc_connector_request(ppc_connector *c, ppc_peer *peer, const ppc_message *m, double timeout,
                          uint8_t **reply, size_t *reply_len);
int ppc_connector_send(ppc_connector *c, ppc_peer *peer, const ppc_message *m);

/* The JSON error reply of section 8. malloc'd. */
char *ppc_error_payload(const char *method_name, const char *error);

/* ---- proxy process (sections 1, 7, 8) ------------------------------------------------------------------------- */
typedef struct {
    ppc_uuid proxy_id;
    char *proxy_name;
    ppc_uuid manager_id;
    char *manager_address;
    int manager_port;
    char *inbound_address;
    int inbound_port;
    bool encrypt;
    char *cipher;
    bool ipc_tls;
    bool manager_dials;
    bool persistent;
    bool socket_logging;
    long compress_threshold;            /* -1 when not given */
    char *log_level;                    /* NULL when not given */
    /* Protocol-specific options the manager appended (--name value), in order. */
    char **extra_names;
    char **extra_values;
    size_t extra_count;
} ppc_proxy_options;

/* Parse the standard command line of section 1. Unknown --name value pairs land in extra_*. Returns PPC_OK, or
 * PPC_ERR_INVALID with a message in err. */
int ppc_proxy_options_parse(int argc, char **argv, ppc_proxy_options *out, char *err, size_t err_len);
void ppc_proxy_options_free(ppc_proxy_options *o);
const char *ppc_proxy_option(const ppc_proxy_options *o, const char *name);

typedef struct {
    ppc_uuid proxy_token;
    ppc_uuid manager_token;
    bool has_key;
    uint8_t key[PPC_KEY_BYTES];
    ppc_tls_material *tls;              /* NULL without --ipc-tls */
} ppc_proxy_secrets;

/* Read the stdin handshake: two tokens, the key with encrypt, the TLS line with ipc_tls. */
int ppc_proxy_read_secrets(FILE *in, bool encrypt, bool ipc_tls, ppc_proxy_secrets *out, char *err, size_t err_len);
void ppc_proxy_secrets_free(ppc_proxy_secrets *s);

typedef struct ppc_proxy ppc_proxy;

/* features: what REGISTER_PEER advertises; NULL for the default ("ping", "set_log_level", "compress",
 * "aead-chacha20poly1305", "aead-aes256gcm"). The options and secrets are copied. */
ppc_proxy *ppc_proxy_new(const ppc_proxy_options *options, const ppc_proxy_secrets *secrets,
                         const char *const *features, size_t feature_count);
ppc_connector *ppc_proxy_connector(ppc_proxy *p);
ppc_peer *ppc_proxy_manager(ppc_proxy *p);
int ppc_proxy_register_handler(ppc_proxy *p, const char *method_name, ppc_handler_fn fn, void *user,
                               bool provides_response);
/* Start the listener, register with the manager (section 7), then serve until SIGTERM, the parent process is gone,
 * or ppc_proxy_stop. Returns the process exit code: 0 after a clean stop, 1 otherwise. Installs a SIGTERM handler. */
int ppc_proxy_run(ppc_proxy *p);
/* Ask a running proxy to stop (from a handler or another thread). */
void ppc_proxy_stop(ppc_proxy *p);
bool ppc_proxy_registered(const ppc_proxy *p);
void ppc_proxy_free(ppc_proxy *p);
/* The PING reply body for this proxy (for tests). malloc'd. */
char *ppc_proxy_health_json(ppc_proxy *p);

/* ---- self test ------------------------------------------------------------------------------------------------ */
/* Check every vector in a test_vectors.json; report failures on out (may be NULL). Returns the failure count, or -1
 * when the file cannot be read or parsed. */
int ppc_selftest_vectors(const char *path, FILE *out);

#ifdef __cplusplus
}
#endif
#endif
