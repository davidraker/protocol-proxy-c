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
#include <sys/types.h>

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
/* Whether records are JSON lines (launched by a manager with stderr a pipe, or json_lines 1). */
bool ppc_log_json_mode(void);
/* Write one JSON record as a line on stderr, whatever the sink. */
void ppc_log_write_json_line(const char *record);

/* The LOG queue (sections 9, 11a): bounded, token-bucket rate limited, drops counted. Records are the malloc'd JSON
 * strings of ppc_log_record_json; push takes ownership (the record is freed when dropped). Thread-safe. */
typedef struct ppc_log_queue ppc_log_queue;
#define PPC_LOG_QUEUE_MAX 2000
#define PPC_LOG_QUEUE_RATE 50.0
#define PPC_LOG_QUEUE_BURST 200
#define PPC_LOG_BATCH_SIZE 64
#define PPC_LOG_FLUSH_INTERVAL 0.2
/* 0 for any argument: the default above. */
ppc_log_queue *ppc_log_queue_new(size_t max_len, double rate, int burst);
void ppc_log_queue_free(ppc_log_queue *q);
/* True when the record was queued, false when it was dropped (and counted). */
bool ppc_log_queue_push(ppc_log_queue *q, char *record);
size_t ppc_log_queue_len(ppc_log_queue *q);
long ppc_log_queue_total_dropped(ppc_log_queue *q);
/* Take up to limit records (all when 0) and the count dropped since the last drain. The array and the records are
 * the caller's to free; NULL when nothing was queued. */
char **ppc_log_queue_drain(ppc_log_queue *q, size_t limit, size_t *count, long *dropped);
/* The LOG payload {"records": [...], "dropped": n}. malloc'd. */
char *ppc_log_batch_json(char *const *records, size_t count, long dropped);
/* Route JSON records into q instead of stderr (NULL: back to stderr). Text-mode records are never queued. */
void ppc_log_set_queue(ppc_log_queue *q);

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
    bool low_priority;                  /* a LOG batch: on a persistent connection, written only when no other frame
                                           is waiting (section 9) */
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
bool ppc_peer_has_key(const ppc_peer *p);
bool ppc_peer_tls(const ppc_peer *p);
bool ppc_peer_persistent(const ppc_peer *p, const ppc_connector *c);
/* The peer's advertised features as a malloc'd list of malloc'd strings (free with ppc_strings_free); NULL when none. */
char **ppc_peer_features(ppc_peer *p, size_t *count);
/* Where the peer listens (set from its registration); address NULL to forget it. */
int ppc_connector_set_peer_address(ppc_connector *c, ppc_peer *p, const char *address, int port);
/* Forget a peer: its frames are refused from now on and its persistent connection is closed. The peer's memory stays
 * valid until the connector is freed (a handler may still hold the pointer), so a replacement with the same id can
 * be added at once. */
void ppc_connector_remove_peer(ppc_connector *c, const ppc_uuid *id);
/* Free a list of strings made by this library. */
void ppc_strings_free(char **list, size_t count);

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

/* ---- JSON helpers used by the manager ------------------------------------------------------------------------- */
ppc_json *ppc_json_clone(const ppc_json *v);

/* ---- manifests (section 1a) ----------------------------------------------------------------------------------- */
/* A proxy.toml: everything a manager needs to launch and key a proxy, as data. Discovery follows the section 1a
 * list: PROTOCOL_PROXY_MANIFESTS (prepended), $XDG_CONFIG_HOME/protocol-proxy/manifests, <prefix>/share/protocol-proxy/
 * manifests (prefix: PROTOCOL_PROXY_PREFIX, else the directory above the running executable's directory),
 * $XDG_CONFIG_DIRS/... (/etc) and $XDG_DATA_DIRS/... (/usr/local/share:/usr/share). */
typedef struct ppc_manifest ppc_manifest;

/* A launch option in the Python kwargs spelling ("inbound_port"), value as a string ("true"/"false" for booleans). */
typedef struct {
    const char *name;
    const char *value;
} ppc_option;

/* source names the file in errors and resolves {manifest_dir}; NULL for a manifest built in memory. */
ppc_manifest *ppc_manifest_parse(const char *text, const char *source, char *err, size_t err_len);
ppc_manifest *ppc_manifest_load(const char *path, char *err, size_t err_len);
/* <dir>/<name>.toml or <dir>/<name>/proxy.toml along the search path; malloc'd path, or NULL with err naming every
 * place looked. */
char *ppc_manifest_locate(const char *name, char *err, size_t err_len);
ppc_manifest *ppc_manifest_find(const char *name, char *err, size_t err_len);
char **ppc_manifest_search_path(size_t *count);
void ppc_manifest_free(ppc_manifest *m);
const char *ppc_manifest_name(const ppc_manifest *m);
const char *ppc_manifest_source(const ppc_manifest *m);         /* NULL for one built in memory */
const char *ppc_manifest_dir(const ppc_manifest *m);            /* "" for one built in memory */
int ppc_manifest_header_version(const ppc_manifest *m);
/* The [environment] table as written (values may carry {python} and {manifest_dir}). */
size_t ppc_manifest_environment(const ppc_manifest *m, const char *const **names, const char *const **values);
/* The environment values with placeholders resolved, parallel to the names of ppc_manifest_environment. malloc'd
 * list of *count strings (free with ppc_strings_free). */
char **ppc_manifest_resolved_environment(const ppc_manifest *m, const char *python, size_t *count);
size_t ppc_manifest_command(const ppc_manifest *m, const char *const **argv);
/* The argv to start the proxy: the command with {python} and {manifest_dir} resolved, then the standard options.
 * malloc'd, NULL-terminated; *argc receives the count. */
char **ppc_manifest_launch_command(const ppc_manifest *m, const char *python, const char *const *standard,
                                   size_t n_standard, size_t *argc);
/* The self-test argv with placeholders resolved, NULL when the manifest has none. */
char **ppc_manifest_self_test_command(const ppc_manifest *m, const char *python, size_t *argc);
/* The process key: a JSON array (the proxy name and the normalised identity options when the manifest names keys,
 * else the caller's unique_remote_id as given). */
ppc_json *ppc_manifest_process_key(const ppc_manifest *m, const char *const *unique_remote_id, size_t id_count,
                                   const ppc_option *options, size_t n_options);
/* The must_match options on which options differs from first: a malloc'd ", "-joined list, NULL when none. */
char *ppc_manifest_conflicts(const ppc_manifest *m, const ppc_option *first, size_t n_first,
                             const ppc_option *options, size_t n_options);
size_t ppc_manifest_must_match(const ppc_manifest *m, const char *const **names);
/* Python's repr of a tuple of the array's items ("('mqtt', 'broker', 1883)"): the proxy name a Python manager gives
 * the same process. malloc'd. */
char *ppc_py_tuple(const ppc_json *key);
/* A launch option's value as the Python manager's str2bool reads it. */
bool ppc_option_bool(const char *value, bool dflt);
const char *ppc_options_get(const ppc_option *options, size_t n, const char *name);

/* ---- log records from launched proxies (section 9) ------------------------------------------------------------ */
/* One record as the manager handles it: rebuilt from a JSON line on a pipe, an entry of a LOG batch, or a plain
 * line. Strings and fields are owned; free with ppc_record_free. */
typedef struct {
    char *logger;           /* the manager-side logger: protocol_proxy.proxies.<manifest>.<proxy> */
    char *remote_name;      /* the proxy's own logger name, or the stream a plain line came from */
    char *channel;          /* "stdout", "stderr" or "socket" */
    int level;
    char *msg;
    char *exc_text;         /* NULL without a traceback */
    char *proxy_name;
    int pid;
    ppc_json *fields;       /* the wire fields of a JSON record; NULL for a plain line */
} ppc_record;

/* Called from the pipe reader threads and the connector's LOG handler: must be thread-safe. */
typedef void (*ppc_record_fn)(const ppc_record *record, void *user);

#define PPC_PROXIES_LOGGER "protocol_proxy.proxies"
#define PPC_LAUNCHED_BY_MANAGER_ENV "_LAUNCHED_BY_PROXY_MANAGER"
char *ppc_proxy_logger_name(const char *manifest_name, const char *proxy_name);
/* 1 and *out filled for a line with content, 0 for an empty line, negative on allocation failure. */
int ppc_record_from_line(const char *line, size_t len, const char *logger, const char *stream, int pid,
                         const char *proxy_name, ppc_record *out);
int ppc_record_from_fields(const ppc_json *fields, const char *logger, const char *channel, int pid,
                           const char *proxy_name, ppc_record *out);
/* The records of one LOG batch ({"records": [...], "dropped": n}; a dropped count becomes one WARNING at the end).
 * malloc'd array of *count records, each to be freed with ppc_record_free. PPC_ERR_INVALID for a bad payload. */
int ppc_records_from_batch(const char *payload, size_t len, const char *logger, int pid, const char *proxy_name,
                           ppc_record **out, size_t *count);
int ppc_record_copy(const ppc_record *in, ppc_record *out);
void ppc_record_free(ppc_record *r);
/* The default handler: the record through ppc_log under its logger name, "[remote] msg". user is ignored. */
void ppc_record_log(const ppc_record *record, void *user);

/* ---- certificate authority (section 5, TLS) ------------------------------------------------------------------- */
/* An in-memory CA, one per manager: EC P-256, 366 days, path length 0. Issues the manager its own certificate and
 * every TLS proxy one naming its id. */
typedef struct ppc_authority ppc_authority;
ppc_authority *ppc_authority_new(const char *name, char *err, size_t err_len);
void ppc_authority_free(ppc_authority *a);
const char *ppc_authority_ca_pem(const ppc_authority *a);
/* common_name is the peer's id (hex); ip_addresses become IP SANs (an unparsable one a DNS SAN). */
ppc_tls_material *ppc_authority_issue(const ppc_authority *a, const char *common_name,
                                      const char *const *ip_addresses, size_t n_addresses, char *err, size_t err_len);
/* The {"ca", "cert", "key"} JSON line (with its newline) a manager writes to a proxy's stdin. malloc'd. */
char *ppc_tls_material_line(const ppc_tls_material *m);

/* ---- manager (sections 1, 1a, 7, 9, 10, 11b) ------------------------------------------------------------------ */
typedef struct ppc_manager ppc_manager;
typedef struct ppc_managed_proxy ppc_managed_proxy;

typedef void (*ppc_lost_fn)(ppc_manager *m, ppc_managed_proxy *p, const char *reason, void *user);

typedef struct {
    const ppc_manifest *manifest;       /* required; must outlive the manager */
    const char *name;                   /* this end's name in log lines (NULL: "Manager") */
    const char *inbound_address;        /* the listener (NULL: "localhost"); proxies are told --manager-address this */
    int inbound_port;                   /* 0: first free port in 22801..22899 */
    bool persistent;                    /* default connection policy toward proxies (a "persistent" option wins) */
    bool encrypt;                       /* give every proxy an AEAD key unless its options say encrypt=false */
    const char *cipher;                 /* "auto" (NULL), "aes-256-gcm", "chacha20-poly1305" */
    bool ipc_tls;                       /* TLS by default for every proxy (an "ipc_tls" option wins) */
    long compress_threshold;            /* 0: 4096; -1: never; PPC_COMPRESS_EVERYTHING */
    double heartbeat_interval;          /* seconds between PINGs (0: 10); negative: no heartbeat */
    double heartbeat_timeout;           /* reply wait (0: 5) */
    int heartbeat_misses;               /* consecutive misses that lose a proxy (0: 3) */
    const char *python;                 /* what {python} resolves to (NULL: $PROTOCOL_PROXY_PYTHON, else python3) */
    const char *const *env_names;       /* added to every proxy's environment after the manifest's */
    const char *const *env_values;
    size_t env_count;
    ppc_record_fn records;              /* receives the proxies' records (NULL: ppc_record_log) */
    void *records_user;
    int proxy_log_level;                /* gates their records and travels as --log-level (0: INFO) */
} ppc_manager_config;

#define PPC_MANAGER_HEARTBEAT_INTERVAL 10.0
#define PPC_MANAGER_HEARTBEAT_TIMEOUT 5.0
#define PPC_MANAGER_HEARTBEAT_MISSES 3
#define PPC_MANAGER_TERMINATE_TIMEOUT 5.0
#define PPC_PYTHON_ENV "PROTOCOL_PROXY_PYTHON"

/* Makes the manager, its CA and its own certificate (so any proxy may be launched with TLS). */
ppc_manager *ppc_manager_new(const ppc_manager_config *config, char *err, size_t err_len);
/* Bind the listener and start accepting. */
int ppc_manager_start(ppc_manager *m);
/* Stop: the listener and connections first, then (with terminate_proxies) SIGTERM to every running proxy and
 * SIGKILL after timeout seconds (0: 5). Idempotent. */
void ppc_manager_stop(ppc_manager *m, bool terminate_proxies, double timeout);
bool ppc_manager_stopped(const ppc_manager *m);
/* Stops (terminating the proxies) and frees everything, including every proxy handle it ever returned. */
void ppc_manager_free(ppc_manager *m);
ppc_connector *ppc_manager_connector(ppc_manager *m);
const ppc_uuid *ppc_manager_id(const ppc_manager *m);
const char *ppc_manager_cipher(const ppc_manager *m);
const char *ppc_manager_python(const ppc_manager *m);
int ppc_manager_local_address(ppc_manager *m, char *address, size_t address_len, int *port);
/* The proxy for unique_remote_id (strings), launching its process when none runs for its key. options are the
 * launch options (Python kwargs spelling): they select the process through the manifest's identity, are checked
 * against its must_match, and travel to the proxy as --name value except the manager-only ones (dial, ssh_host,
 * ssh_options, ssh_forward, remote_python, remote_env, manager_callbacks). "encrypt", "cipher", "ipc_tls",
 * "persistent" and "manager_dials" also configure this end; "dial" ("host:port") is where to reach a manager_dials
 * proxy (default its inbound_address:inbound_port). NULL with err on failure. */
ppc_managed_proxy *ppc_manager_get_proxy(ppc_manager *m, const char *const *unique_remote_id, size_t id_count,
                                         const ppc_option *options, size_t n_options, char *err, size_t err_len);
/* PPC_OK once registered; PPC_ERR_TIMEOUT (the proxy is then lost and its process terminated) or PPC_ERR_CONNECTION
 * (lost meanwhile). */
int ppc_manager_wait_registered(ppc_manager *m, ppc_managed_proxy *p, double timeout);
int ppc_manager_request(ppc_manager *m, ppc_managed_proxy *p, const ppc_message *msg, double timeout,
                        uint8_t **reply, size_t *reply_len);
int ppc_manager_send(ppc_manager *m, ppc_managed_proxy *p, const ppc_message *msg);
/* SET_LOG_LEVEL to the proxy and gate its records here at the same level; the reply ({"level": ...}) in *reply. */
int ppc_manager_set_proxy_log_level(ppc_manager *m, ppc_managed_proxy *p, int level, double timeout,
                                    uint8_t **reply, size_t *reply_len);
/* Called whenever a proxy this manager launched is lost (process exit, missed heartbeats, no registration). By then
 * it is forgotten, so the next get_proxy for its key launches afresh. */
void ppc_manager_on_proxy_lost(ppc_manager *m, ppc_lost_fn fn, void *user);
/* Stop a proxy's process (SIGTERM, SIGKILL after timeout; 0: 5 s) without forgetting it: the watcher then loses it. */
void ppc_manager_terminate(ppc_manager *m, ppc_managed_proxy *p, double timeout);
/* Every proxy's liveness by name: state, last_seen, missed, features, persistent, connected, pid, report. malloc'd. */
char *ppc_manager_health_json(ppc_manager *m);
/* Run the manifest's self-test command, if any: PPC_OK when it passes or there is none, else PPC_ERR_IO with err. */
int ppc_manager_self_test(ppc_manager *m, char *err, size_t err_len);
/* The current proxy with that id, or NULL. */
ppc_managed_proxy *ppc_manager_proxy_by_id(ppc_manager *m, const ppc_uuid *id);
/* The current proxies (malloc'd array of *count handles). */
ppc_managed_proxy **ppc_manager_proxies(ppc_manager *m, size_t *count);

/* A launched proxy as the manager sees it. Handles stay valid until the manager is freed. */
ppc_peer *ppc_managed_proxy_peer(ppc_managed_proxy *p);
const ppc_uuid *ppc_managed_proxy_id(const ppc_managed_proxy *p);
const char *ppc_managed_proxy_name(const ppc_managed_proxy *p);
const ppc_json *ppc_managed_proxy_key(const ppc_managed_proxy *p);
size_t ppc_managed_proxy_command(const ppc_managed_proxy *p, const char *const **argv);
/* launching, registered, healthy, unhealthy, lost. */
const char *ppc_managed_proxy_state(ppc_managed_proxy *p);
bool ppc_managed_proxy_registered(ppc_managed_proxy *p);
bool ppc_managed_proxy_lost(ppc_managed_proxy *p);
const char *ppc_managed_proxy_lost_reason(ppc_managed_proxy *p);      /* NULL while current */
/* The AEAD the proxy said it encrypts with in REGISTER_PEER (NULL before, or when it does not encrypt). */
const char *ppc_managed_proxy_cipher(ppc_managed_proxy *p);
/* The last PING report (malloc'd JSON text), NULL before any. */
char *ppc_managed_proxy_health_json(ppc_managed_proxy *p);
int ppc_managed_proxy_log_level(ppc_managed_proxy *p);
pid_t ppc_managed_proxy_pid(ppc_managed_proxy *p);
bool ppc_managed_proxy_running(ppc_managed_proxy *p);
/* Wait up to timeout seconds for the process to exit; true when it has, with its exit code (a negative signal
 * number when it was killed) in *code. */
bool ppc_managed_proxy_wait(ppc_managed_proxy *p, double timeout, int *code);

/* ---- conformance (section 12) --------------------------------------------------------------------------------- */
/* The harness: launch a proxy through this manager and check every clause of the contract (the Python
 * protocol-proxy-conformance command's checks, by the same names). */
typedef struct {
    const ppc_option *launch_options;   /* passed to every launch */
    size_t n_launch_options;
    const char *echo_method;            /* a method that replies with its payload; NULL skips the payload checks */
    bool tls;                           /* also run the TLS session */
    bool manager_dials;                 /* also run the manager-initiated registration session */
    double timeout;                     /* registration and each reply (0: 20) */
    const char *python;                 /* what {python} resolves to (NULL: the manager's default) */
    ppc_record_fn records;              /* where the proxies' records go besides the harness (NULL: nowhere) */
    void *records_user;
} ppc_conformance_options;

typedef struct {
    char *name;
    bool passed;
    bool skipped;
    char *detail;
} ppc_check;

typedef struct {
    const ppc_manifest *manifest;
    ppc_check *checks;
    size_t n_checks;
    char **features;
    size_t n_features;
} ppc_conformance_report;

#define PPC_CONFORMANCE_LOG_BATCH_WAIT 3.0
ppc_conformance_report *ppc_conformance_run(const ppc_manifest *m, const ppc_conformance_options *options);
bool ppc_conformance_ok(const ppc_conformance_report *r);
char *ppc_conformance_text(const ppc_conformance_report *r);
char *ppc_conformance_json(const ppc_conformance_report *r);
void ppc_conformance_report_free(ppc_conformance_report *r);

/* ---- self test ------------------------------------------------------------------------------------------------ */
/* Check every vector in a test_vectors.json; report failures on out (may be NULL). Returns the failure count, or -1
 * when the file cannot be read or parsed. */
int ppc_selftest_vectors(const char *path, FILE *out);

#ifdef __cplusplus
}
#endif
#endif
