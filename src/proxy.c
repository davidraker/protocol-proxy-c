/* The proxy process (sections 1, 7, 8, 9): command line, stdin handshake, registration with the manager, the core
 * methods PING and SET_LOG_LEVEL, LOG batches over the socket, the parent-PID watch and SIGTERM handling. */
#include "internal.h"

#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>

#define TOKEN_HEX_LENGTH 32
#define KEY_HEX_LENGTH 64
#define REGISTRATION_ATTEMPTS 2
#define REGISTRATION_TIMEOUT 5.0
#define REGISTRATION_RETRY_DELAY 20.0
#define MANAGER_WATCH_INTERVAL_MS 1000
#define MANAGER_WAIT_LOG_INTERVAL 30.0
#define HARD_EXIT_GRACE 15

static const char *const DEFAULT_FEATURES[] = {"ping", "set_log_level", "compress", "aead-chacha20poly1305", "aead-aes256gcm"};
#define LOG_FEATURE "log"
#define LOG_FLUSH_POLL_MS 20

struct ppc_proxy {
    ppc_proxy_options opts;
    ppc_proxy_secrets secrets;
    char **features;
    size_t n_features;
    ppc_connector *c;
    ppc_peer *manager;
    double started_at;
    pid_t parent;
    int wake_pipe[2];                   /* 't': SIGTERM, 's': stop requested, 'x': wake */
    atomic_bool stop;
    bool registered;
    bool sigterm;
    bool manager_lost;
    pthread_t watch_thread;
    bool watching;
    ppc_log_queue *log_queue;           /* LOG batches over the socket once registered (NULL: records go to stderr) */
    pthread_t flush_thread;
    bool flushing;
    atomic_bool flush_stop;
};

/* Whether this proxy will log over the socket once registered: asked to (--socket-logging, default true) and
 * launched by a manager with stderr a pipe (the JSON-lines condition of section 9). */
static bool socket_logging_applies(const ppc_proxy_options *options) {
    return options->socket_logging && ppc_log_json_mode();
}

static ppc_proxy *signal_target;        /* the proxy whose SIGTERM handler is installed */

/* ---- options -------------------------------------------------------------------------------------------------- */
static int str2bool(const char *value, bool *out) {
    char lowered[16];
    size_t n = strlen(value);
    while (n && (value[n - 1] == ' ' || value[n - 1] == '\t')) n--;
    while (n && (*value == ' ' || *value == '\t')) { value++; n--; }
    if (n >= sizeof lowered) return PPC_ERR_INVALID;
    for (size_t i = 0; i < n; i++) lowered[i] = (char)tolower((unsigned char)value[i]);
    lowered[n] = '\0';
    static const char *const yes[] = {"1", "true", "t", "yes", "y", "on"};
    static const char *const no[] = {"0", "false", "f", "no", "n", "off", ""};
    for (size_t i = 0; i < sizeof yes / sizeof *yes; i++) if (strcmp(lowered, yes[i]) == 0) { *out = true; return PPC_OK; }
    for (size_t i = 0; i < sizeof no / sizeof *no; i++) if (strcmp(lowered, no[i]) == 0) { *out = false; return PPC_OK; }
    return PPC_ERR_INVALID;
}

static int add_extra(ppc_proxy_options *o, const char *name, const char *value) {
    char **names = realloc(o->extra_names, (o->extra_count + 1) * sizeof *names);
    if (names == NULL) return PPC_ERR_NOMEM;
    o->extra_names = names;
    char **values = realloc(o->extra_values, (o->extra_count + 1) * sizeof *values);
    if (values == NULL) return PPC_ERR_NOMEM;
    o->extra_values = values;
    names[o->extra_count] = ppc_strdup(name);
    values[o->extra_count] = ppc_strdup(value);
    if (names[o->extra_count] == NULL || values[o->extra_count] == NULL) return PPC_ERR_NOMEM;
    o->extra_count++;
    return PPC_OK;
}

static int set_string(char **slot, const char *value) {
    char *copy = ppc_strdup(value);
    if (copy == NULL) return PPC_ERR_NOMEM;
    free(*slot);
    *slot = copy;
    return PPC_OK;
}

int ppc_proxy_options_parse(int argc, char **argv, ppc_proxy_options *o, char *err, size_t err_len) {
    if (o == NULL) return PPC_ERR_INVALID;
    if (err && err_len) err[0] = '\0';
    memset(o, 0, sizeof *o);
    o->manager_port = 22801;
    o->socket_logging = true;
    o->compress_threshold = -1;
    bool have_proxy_id = false, have_manager_id = false;
    int rc = PPC_OK;
    if ((rc = set_string(&o->manager_address, "localhost")) != PPC_OK) return rc;
    if ((rc = set_string(&o->inbound_address, "localhost")) != PPC_OK) return rc;
    if ((rc = set_string(&o->cipher, "auto")) != PPC_OK) return rc;
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strncmp(arg, "--", 2) != 0) {
            if (err) snprintf(err, err_len, "unexpected argument %s (every option is --name value)", arg);
            return PPC_ERR_INVALID;
        }
        char name[128];
        const char *value;
        const char *eq = strchr(arg, '=');
        if (eq) {
            snprintf(name, sizeof name, "%.*s", (int)(eq - arg - 2), arg + 2);
            value = eq + 1;
        } else {
            snprintf(name, sizeof name, "%s", arg + 2);
            if (i + 1 >= argc) {
                if (err) snprintf(err, err_len, "option %s needs a value", arg);
                return PPC_ERR_INVALID;
            }
            value = argv[++i];
        }
        for (char *p = name; *p; p++) if (*p == '-') *p = '_';
        bool flag;
        if (strcmp(name, "proxy_id") == 0) {
            if (ppc_uuid_parse(value, &o->proxy_id) != PPC_OK) { if (err) snprintf(err, err_len, "--proxy-id is not a UUID"); return PPC_ERR_INVALID; }
            have_proxy_id = true;
        } else if (strcmp(name, "manager_id") == 0) {
            if (ppc_uuid_parse(value, &o->manager_id) != PPC_OK) { if (err) snprintf(err, err_len, "--manager-id is not a UUID"); return PPC_ERR_INVALID; }
            have_manager_id = true;
        } else if (strcmp(name, "proxy_name") == 0) {
            rc = set_string(&o->proxy_name, value);
        } else if (strcmp(name, "manager_address") == 0) {
            rc = set_string(&o->manager_address, value);
        } else if (strcmp(name, "inbound_address") == 0) {
            rc = set_string(&o->inbound_address, value);
        } else if (strcmp(name, "manager_port") == 0) {
            o->manager_port = atoi(value);
        } else if (strcmp(name, "inbound_port") == 0) {
            o->inbound_port = atoi(value);
        } else if (strcmp(name, "compress_threshold") == 0) {
            o->compress_threshold = atol(value);
        } else if (strcmp(name, "cipher") == 0) {
            if (strcmp(value, "auto") != 0 && strcmp(value, "aes-256-gcm") != 0 && strcmp(value, PPC_BASELINE_CIPHER) != 0) {
                if (err) snprintf(err, err_len, "--cipher must be auto, aes-256-gcm or chacha20-poly1305");
                return PPC_ERR_INVALID;
            }
            rc = set_string(&o->cipher, value);
        } else if (strcmp(name, "log_level") == 0) {
            rc = set_string(&o->log_level, value);
        } else if (strcmp(name, "encrypt") == 0 || strcmp(name, "ipc_tls") == 0 || strcmp(name, "manager_dials") == 0
                   || strcmp(name, "persistent") == 0 || strcmp(name, "socket_logging") == 0) {
            if (str2bool(value, &flag) != PPC_OK) {
                if (err) snprintf(err, err_len, "--%s expects a boolean, got \"%s\"", name, value);
                return PPC_ERR_INVALID;
            }
            if (strcmp(name, "encrypt") == 0) o->encrypt = flag;
            else if (strcmp(name, "ipc_tls") == 0) o->ipc_tls = flag;
            else if (strcmp(name, "manager_dials") == 0) o->manager_dials = flag;
            else if (strcmp(name, "persistent") == 0) o->persistent = flag;
            else o->socket_logging = flag;
        } else {
            rc = add_extra(o, name, value);
        }
        if (rc != PPC_OK) return rc;
    }
    if (!have_proxy_id || !have_manager_id || o->proxy_name == NULL) {
        if (err) snprintf(err, err_len, "--proxy-id, --proxy-name and --manager-id are required");
        return PPC_ERR_INVALID;
    }
    return PPC_OK;
}

void ppc_proxy_options_free(ppc_proxy_options *o) {
    if (o == NULL) return;
    free(o->proxy_name);
    free(o->manager_address);
    free(o->inbound_address);
    free(o->cipher);
    free(o->log_level);
    for (size_t i = 0; i < o->extra_count; i++) { free(o->extra_names[i]); free(o->extra_values[i]); }
    free(o->extra_names);
    free(o->extra_values);
    memset(o, 0, sizeof *o);
}

const char *ppc_proxy_option(const ppc_proxy_options *o, const char *name) {
    for (size_t i = 0; i < o->extra_count; i++) if (strcmp(o->extra_names[i], name) == 0) return o->extra_values[i];
    return NULL;
}

static int options_copy(ppc_proxy_options *dst, const ppc_proxy_options *src) {
    memset(dst, 0, sizeof *dst);
    *dst = *src;
    dst->proxy_name = dst->manager_address = dst->inbound_address = dst->cipher = dst->log_level = NULL;
    dst->extra_names = dst->extra_values = NULL;
    dst->extra_count = 0;
    if ((src->proxy_name && (dst->proxy_name = ppc_strdup(src->proxy_name)) == NULL)
        || (src->manager_address && (dst->manager_address = ppc_strdup(src->manager_address)) == NULL)
        || (src->inbound_address && (dst->inbound_address = ppc_strdup(src->inbound_address)) == NULL)
        || (src->cipher && (dst->cipher = ppc_strdup(src->cipher)) == NULL)
        || (src->log_level && (dst->log_level = ppc_strdup(src->log_level)) == NULL))
        return PPC_ERR_NOMEM;
    for (size_t i = 0; i < src->extra_count; i++)
        if (add_extra(dst, src->extra_names[i], src->extra_values[i]) != PPC_OK) return PPC_ERR_NOMEM;
    return PPC_OK;
}

/* ---- stdin handshake ------------------------------------------------------------------------------------------ */
static size_t read_exact(FILE *in, char *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        size_t r = fread(buf + got, 1, n - got, in);
        if (r == 0) break;
        got += r;
    }
    return got;
}

int ppc_proxy_read_secrets(FILE *in, bool encrypt, bool ipc_tls, ppc_proxy_secrets *out, char *err, size_t err_len) {
    if (in == NULL || out == NULL) return PPC_ERR_INVALID;
    memset(out, 0, sizeof *out);
    char tokens[2 * TOKEN_HEX_LENGTH + 1];
    size_t got = read_exact(in, tokens, 2 * TOKEN_HEX_LENGTH);
    if (got != 2 * TOKEN_HEX_LENGTH) {
        if (err) snprintf(err, err_len, "Expected %d hex characters (proxy token + manager token) on stdin, got %zu bytes."
                          " Proxies are meant to be launched by a ProtocolProxyManager.", 2 * TOKEN_HEX_LENGTH, got);
        return PPC_ERR_INVALID;
    }
    tokens[2 * TOKEN_HEX_LENGTH] = '\0';
    if (ppc_hex_decode(tokens, TOKEN_HEX_LENGTH, out->proxy_token.b, 16) != PPC_OK
        || ppc_hex_decode(tokens + TOKEN_HEX_LENGTH, TOKEN_HEX_LENGTH, out->manager_token.b, 16) != PPC_OK) {
        if (err) snprintf(err, err_len, "The tokens on stdin are not hex.");
        return PPC_ERR_INVALID;
    }
    if (encrypt) {
        char key_hex[KEY_HEX_LENGTH + 1];
        got = read_exact(in, key_hex, KEY_HEX_LENGTH);
        if (got != KEY_HEX_LENGTH || ppc_hex_decode(key_hex, KEY_HEX_LENGTH, out->key, PPC_KEY_BYTES) != PPC_OK) {
            if (err) snprintf(err, err_len, "--encrypt is set but no %d-byte key followed the tokens on stdin (got %zu bytes).",
                              PPC_KEY_BYTES, got);
            return PPC_ERR_INVALID;
        }
        out->has_key = true;
    }
    if (ipc_tls) {
        char *line = NULL;
        size_t cap = 0;
        ssize_t n = getline(&line, &cap, in);
        if (n <= 0 || strspn(line, " \t\r\n") == (size_t)n) {
            free(line);
            if (err) snprintf(err, err_len, "--ipc-tls is set but no TLS material (one JSON line) followed on stdin.");
            return PPC_ERR_INVALID;
        }
        int rc = ppc_tls_material_parse(line, (size_t)n, &out->tls);
        free(line);
        if (rc != PPC_OK) {
            if (err) snprintf(err, err_len, "The TLS material on stdin is not a {\"ca\", \"cert\", \"key\"} JSON line.");
            return rc;
        }
    }
    return PPC_OK;
}

void ppc_proxy_secrets_free(ppc_proxy_secrets *s) {
    if (s == NULL) return;
    ppc_tls_material_free(s->tls);
    memset(s, 0, sizeof *s);
}

/* ---- core methods --------------------------------------------------------------------------------------------- */
char *ppc_proxy_health_json(ppc_proxy *p) {
    ppc_json *o = ppc_json_new_object();
    if (o == NULL) return NULL;
    double uptime = ppc_now() - p->started_at;
    uptime = (double)((long long)(uptime * 1000.0 + 0.5)) / 1000.0;
    ppc_json_object_set(o, "uptime", ppc_json_new_number(uptime));
    ppc_json_object_set(o, "remotes", ppc_json_new_integer((long long)ppc_connector_remote_count(p->c)));
    ppc_json_object_set(o, "busy", ppc_json_new_bool(false));
    double last = ppc_connector_last_activity(p->c);
    if (last > 0) {
        char iso[48];
        ppc_iso8601(last, iso, sizeof iso);
        ppc_json_object_set(o, "last_activity", ppc_json_new_string(iso));
    } else {
        ppc_json_object_set(o, "last_activity", ppc_json_new_null());
    }
    char *text = ppc_json_dump(o);
    ppc_json_free(o);
    return text;
}

static int handle_ping(ppc_connector *c, const ppc_header *h, const uint8_t *payload, size_t len, uint8_t **reply,
                       size_t *reply_len, void *user) {
    (void)c; (void)h; (void)payload; (void)len;
    char *text = ppc_proxy_health_json(user);
    if (text == NULL) return PPC_ERR_NOMEM;
    *reply = (uint8_t *)text;
    *reply_len = strlen(text);
    return PPC_OK;
}

static int handle_set_log_level(ppc_connector *c, const ppc_header *h, const uint8_t *payload, size_t len,
                                uint8_t **reply, size_t *reply_len, void *user) {
    (void)h; (void)user;
    char err[128];
    ppc_json *body = ppc_json_parse((const char *)payload, len, err, sizeof err);
    const ppc_json *level = ppc_json_get(body, "level");
    int value = -1;
    if (level && level->type == PPC_JSON_STRING) value = ppc_log_level_from_name(level->string);
    else if (level && level->type == PPC_JSON_NUMBER && level->is_integer && level->integer >= 0) value = (int)level->integer;
    char *text;
    if (body == NULL || value < 0) {
        char message[200];
        snprintf(message, sizeof message, "Invalid log level: %s", body == NULL ? err : (level && level->type == PPC_JSON_STRING ? level->string : "missing or not a level"));
        text = ppc_error_payload("SET_LOG_LEVEL", message);
    } else {
        ppc_log_set_level(value);
        LOG_INFO("%s: log level set to %s.", ppc_connector_name(c), ppc_log_level_name(value));
        ppc_json *o = ppc_json_new_object();
        ppc_json_object_set(o, "level", ppc_json_new_string(ppc_log_level_name(value)));
        text = ppc_json_dump(o);
        ppc_json_free(o);
    }
    ppc_json_free(body);
    if (text == NULL) return PPC_ERR_NOMEM;
    *reply = (uint8_t *)text;
    *reply_len = strlen(text);
    return PPC_OK;
}

/* ---- construction --------------------------------------------------------------------------------------------- */
ppc_proxy *ppc_proxy_new(const ppc_proxy_options *options, const ppc_proxy_secrets *secrets,
                         const char *const *features, size_t feature_count) {
    if (options == NULL || secrets == NULL) return NULL;
    if (options->encrypt && !secrets->has_key) { LOG_ERROR("%s: --encrypt is set but no key was provided on stdin.", options->proxy_name); return NULL; }
    if (options->ipc_tls && secrets->tls == NULL) { LOG_ERROR("%s: --ipc-tls is set but no TLS material was provided on stdin.", options->proxy_name); return NULL; }
    ppc_proxy *p = calloc(1, sizeof *p);
    if (p == NULL) return NULL;
    p->wake_pipe[0] = p->wake_pipe[1] = -1;
    atomic_init(&p->stop, false);
    if (options_copy(&p->opts, options) != PPC_OK) { ppc_proxy_free(p); return NULL; }
    p->secrets = *secrets;
    p->secrets.tls = NULL;
    if (secrets->tls) {
        p->secrets.tls = calloc(1, sizeof *p->secrets.tls);
        if (p->secrets.tls == NULL || (p->secrets.tls->ca = ppc_strdup(secrets->tls->ca)) == NULL
            || (p->secrets.tls->cert = ppc_strdup(secrets->tls->cert)) == NULL
            || (p->secrets.tls->key = ppc_strdup(secrets->tls->key)) == NULL) { ppc_proxy_free(p); return NULL; }
    }
    bool add_log = false;
    if (features == NULL) {
        features = DEFAULT_FEATURES;
        feature_count = sizeof DEFAULT_FEATURES / sizeof *DEFAULT_FEATURES;
        add_log = socket_logging_applies(options);      /* "log" only when LOG batches will actually be sent */
    }
    p->features = calloc(feature_count + 1, sizeof *p->features);
    if (p->features == NULL) { ppc_proxy_free(p); return NULL; }
    for (size_t i = 0; i < feature_count; i++)
        if ((p->features[p->n_features] = ppc_strdup(features[i])) != NULL) p->n_features++;
    if (add_log && (p->features[p->n_features] = ppc_strdup(LOG_FEATURE)) != NULL) p->n_features++;
    ppc_connector_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.proxy_id = options->proxy_id;
    cfg.token = secrets->proxy_token;
    cfg.proxy_name = options->proxy_name;
    cfg.inbound_address = options->inbound_address;
    cfg.inbound_port = options->inbound_port;
    cfg.persistent = options->persistent;
    cfg.compress_threshold = options->compress_threshold < 0 ? 0
                             : options->compress_threshold == 0 ? PPC_COMPRESS_EVERYTHING : options->compress_threshold;
    cfg.cipher = options->cipher;
    cfg.tls = p->secrets.tls;
    cfg.tls_accept_plain = false;           /* a proxy with TLS material accepts TLS only */
    p->c = ppc_connector_new(&cfg);
    if (p->c == NULL) { ppc_proxy_free(p); return NULL; }
    p->manager = ppc_connector_add_peer(p->c, &options->manager_id, &secrets->manager_token,
                                        options->manager_dials ? NULL : options->manager_address,
                                        options->manager_dials ? 0 : options->manager_port,
                                        secrets->has_key ? secrets->key : NULL, -1, options->ipc_tls);
    if (p->manager == NULL) { ppc_proxy_free(p); return NULL; }
    ppc_connector_register_handler(p->c, "SET_LOG_LEVEL", NULL, handle_set_log_level, p, true);
    ppc_connector_register_handler(p->c, "PING", NULL, handle_ping, p, true);
    p->started_at = ppc_now();
    p->parent = getppid();
    if (pipe2(p->wake_pipe, O_CLOEXEC | O_NONBLOCK) != 0) { ppc_proxy_free(p); return NULL; }
    return p;
}

ppc_connector *ppc_proxy_connector(ppc_proxy *p) { return p->c; }
ppc_peer *ppc_proxy_manager(ppc_proxy *p) { return p->manager; }
bool ppc_proxy_registered(const ppc_proxy *p) { return p->registered; }

int ppc_proxy_register_handler(ppc_proxy *p, const char *method_name, ppc_handler_fn fn, void *user,
                               bool provides_response) {
    return ppc_connector_register_handler(p->c, method_name, NULL, fn, user, provides_response);
}

void ppc_proxy_free(ppc_proxy *p) {
    if (p == NULL) return;
    if (signal_target == p) signal_target = NULL;
    ppc_connector_free(p->c);
    ppc_proxy_options_free(&p->opts);
    ppc_proxy_secrets_free(&p->secrets);
    for (size_t i = 0; i < p->n_features; i++) free(p->features[i]);
    free(p->features);
    if (p->wake_pipe[0] >= 0) close(p->wake_pipe[0]);
    if (p->wake_pipe[1] >= 0) close(p->wake_pipe[1]);
    ppc_log_queue_free(p->log_queue);
    free(p);
}

/* ---- logging over the socket (section 9) ---------------------------------------------------------------------- */
static void write_records_to_stderr(char **records, size_t count) {
    for (size_t i = 0; i < count; i++) { ppc_log_write_json_line(records[i]); free(records[i]); }
    free(records);
}

/* Ship one LOG batch (no response expected). Records the connector cannot send go to stderr instead. */
static void flush_logs(ppc_proxy *p) {
    size_t count = 0;
    long dropped = 0;
    char **records = ppc_log_queue_drain(p->log_queue, PPC_LOG_BATCH_SIZE, &count, &dropped);
    if (count == 0 && dropped == 0) return;
    char *payload = ppc_log_batch_json(records, count, dropped);
    int rc = PPC_ERR_NOMEM;
    if (payload) {
        ppc_message m = {"LOG", (const uint8_t *)payload, strlen(payload), false, NULL, 2, true};
        rc = ppc_connector_send(p->c, p->manager, &m);
        free(payload);
    }
    if (rc != PPC_OK) write_records_to_stderr(records, count);
    else { for (size_t i = 0; i < count; i++) free(records[i]); free(records); }
}

/* Flush every PPC_LOG_FLUSH_INTERVAL seconds, or as soon as PPC_LOG_BATCH_SIZE records are queued. */
static void *flush_thread(void *arg) {
    ppc_proxy *p = arg;
    while (!atomic_load(&p->flush_stop)) {
        double deadline = ppc_monotonic() + PPC_LOG_FLUSH_INTERVAL;
        while (!atomic_load(&p->flush_stop) && ppc_monotonic() < deadline && ppc_log_queue_len(p->log_queue) < PPC_LOG_BATCH_SIZE) {
            struct timespec ts = {0, LOG_FLUSH_POLL_MS * 1000000L};
            nanosleep(&ts, NULL);
        }
        flush_logs(p);
    }
    return NULL;
}

/* After registration: route records into the queue and start the flusher. The switch itself is the first record
 * over the socket. */
static void start_socket_logging(ppc_proxy *p) {
    if (!socket_logging_applies(&p->opts) || p->log_queue != NULL) return;
    p->log_queue = ppc_log_queue_new(0, 0, 0);
    if (p->log_queue == NULL) return;
    atomic_store(&p->flush_stop, false);
    if (pthread_create(&p->flush_thread, NULL, flush_thread, p) != 0) {
        LOG_WARNING("%s: unable to start the log flusher; logging stays on stderr.", p->opts.proxy_name);
        ppc_log_queue_free(p->log_queue);
        p->log_queue = NULL;
        return;
    }
    p->flushing = true;
    ppc_log_set_queue(p->log_queue);
    LOG_INFO("%s: logging over the IPC socket from here on.", p->opts.proxy_name);
}

/* At stop: records go back to stderr, the flusher ends, and whatever is still queued is drained to stderr. */
static void stop_socket_logging(ppc_proxy *p) {
    if (p->log_queue == NULL) return;
    ppc_log_set_queue(NULL);
    if (p->flushing) {
        atomic_store(&p->flush_stop, true);
        pthread_join(p->flush_thread, NULL);
        p->flushing = false;
    }
    size_t count = 0;
    long dropped = 0;
    char **records = ppc_log_queue_drain(p->log_queue, 0, &count, &dropped);
    write_records_to_stderr(records, count);
    long total = ppc_log_queue_total_dropped(p->log_queue);
    if (total) LOG_WARNING("%s: %ld log record(s) were dropped by the LOG queue (rate or size limit).", p->opts.proxy_name, total);
    ppc_log_queue_free(p->log_queue);
    p->log_queue = NULL;
}

/* ---- lifecycle ------------------------------------------------------------------------------------------------ */
static void wake(ppc_proxy *p, char why) {
    if (p->wake_pipe[1] >= 0) { ssize_t n = write(p->wake_pipe[1], &why, 1); (void)n; }
}

void ppc_proxy_stop(ppc_proxy *p) {
    if (p == NULL) return;
    atomic_store(&p->stop, true);
    wake(p, 's');
}

static void on_sigterm(int sig) {
    (void)sig;
    ppc_proxy *p = signal_target;
    if (p) wake(p, 't');            /* async-signal-safe: the watch thread does the rest */
}

static void *hard_exit_thread(void *arg) {
    (void)arg;
    struct timespec ts = {HARD_EXIT_GRACE, 0};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
    LOG_ERROR("still running %d s after a stop was requested; exiting now.", HARD_EXIT_GRACE);
    _exit(1);
}

static void arm_hard_exit(void) {
    static bool armed = false;
    if (armed) return;
    armed = true;
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &attr, hard_exit_thread, NULL);
    pthread_attr_destroy(&attr);
}

/* Watches the parent process and the wake pipe; stops the connector when either says so. */
static void *watch_thread(void *arg) {
    ppc_proxy *p = arg;
    struct pollfd pfd = {p->wake_pipe[0], POLLIN, 0};
    while (!atomic_load(&p->stop)) {
        int n = poll(&pfd, 1, MANAGER_WATCH_INTERVAL_MS);
        if (n > 0) {
            char why[16];
            ssize_t got = read(p->wake_pipe[0], why, sizeof why);
            for (ssize_t i = 0; i < got; i++) {
                if (why[i] == 't') { p->sigterm = true; atomic_store(&p->stop, true); }
                if (why[i] == 's') atomic_store(&p->stop, true);
            }
        } else if (n < 0 && errno != EINTR) {
            break;
        }
        if (getppid() != p->parent) {
            p->manager_lost = true;
            atomic_store(&p->stop, true);
        }
    }
    if (p->sigterm) LOG_INFO("%s: received SIGTERM; stopping.", p->opts.proxy_name);
    if (p->manager_lost) LOG_WARNING("%s: the manager process (%ld) is gone. Stopping.", p->opts.proxy_name, (long)p->parent);
    if (p->sigterm || p->manager_lost) arm_hard_exit();
    ppc_connector_stop(p->c);
    return NULL;
}

static bool registration_accepted(ppc_proxy *p, const uint8_t *reply, size_t len) {
    char err[64];
    ppc_json *v = ppc_json_parse((const char *)reply, len, err, sizeof err);
    if (v == NULL) return false;
    bool ok = false;
    if (v->type == PPC_JSON_OBJECT) {
        const ppc_json *features = ppc_json_get(v, "features");
        if (features && features->type == PPC_JSON_ARRAY) {
            const char **names = calloc(features->count ? features->count : 1, sizeof *names);
            size_t n = 0;
            for (size_t i = 0; names && i < features->count; i++)
                if (features->items[i]->type == PPC_JSON_STRING) names[n++] = features->items[i]->string;
            ppc_peer_set_features(p->manager, names, n);
            free(names);
        } else {
            ppc_peer_set_features(p->manager, NULL, 0);
        }
        const ppc_json *registered = ppc_json_get(v, "registered");
        if (registered) ok = registered->type == PPC_JSON_BOOL ? registered->boolean : registered->type != PPC_JSON_NULL;
        else ok = strcmp(ppc_json_get_string(v, "status", ""), "error") != 0;
    } else if (v->type == PPC_JSON_BOOL) {
        ok = v->boolean;
    }
    ppc_json_free(v);
    return ok;
}

static char *registration_payload(ppc_proxy *p) {
    char address[64];
    int port = 0;
    ppc_connector_local_address(p->c, address, sizeof address, &port);
    char hex[33];
    ppc_json *o = ppc_json_new_object();
    if (o == NULL) return NULL;
    ppc_json_object_set(o, "address", ppc_json_new_string(address));
    ppc_json_object_set(o, "port", ppc_json_new_integer(port));
    ppc_uuid_hex(&p->opts.proxy_id, hex);
    ppc_json_object_set(o, "proxy_id", ppc_json_new_string(hex));
    ppc_uuid_hex(&p->secrets.proxy_token, hex);
    ppc_json_object_set(o, "token", ppc_json_new_string(hex));
    ppc_json *features = ppc_json_new_array();
    for (size_t i = 0; i < p->n_features; i++) ppc_json_array_append(features, ppc_json_new_string(p->features[i]));
    ppc_json_object_set(o, "features", features);
    ppc_json_object_set(o, "cipher", ppc_json_new_string(ppc_connector_cipher(p->c)));
    char *text = ppc_json_dump(o);
    ppc_json_free(o);
    return text;
}

/* Sleep up to seconds, returning early when the proxy is stopping. */
static void stoppable_sleep(ppc_proxy *p, double seconds) {
    double deadline = ppc_monotonic() + seconds;
    while (!atomic_load(&p->stop) && !ppc_connector_stopping(p->c)) {
        double left = deadline - ppc_monotonic();
        if (left <= 0) break;
        struct timespec ts = {0, left > 0.1 ? 100000000L : (long)(left * 1e9)};
        nanosleep(&ts, NULL);
    }
}

static bool wait_for_manager(ppc_proxy *p) {
    double waited = 0, next_log = 0;
    while (!atomic_load(&p->stop) && !ppc_peer_linked(p->manager)) {
        if (waited >= next_log) {
            LOG_INFO("%s: waiting for the manager to connect to %s:%d.", p->opts.proxy_name, p->opts.inbound_address, p->opts.inbound_port);
            next_log = waited + MANAGER_WAIT_LOG_INTERVAL;
        }
        stoppable_sleep(p, 0.1);
        waited += 0.1;
    }
    return ppc_peer_linked(p->manager);
}

static bool send_registration(ppc_proxy *p) {
    if (p->opts.manager_dials && !wait_for_manager(p)) return false;
    for (int attempt = 1; attempt <= REGISTRATION_ATTEMPTS && !atomic_load(&p->stop); attempt++) {
        char *payload = registration_payload(p);
        if (payload == NULL) return false;
        ppc_message m = {"REGISTER_PEER", (const uint8_t *)payload, strlen(payload), true, NULL, 2, false};
        uint8_t *reply = NULL;
        size_t reply_len = 0;
        int rc = ppc_connector_request(p->c, p->manager, &m, REGISTRATION_TIMEOUT, &reply, &reply_len);
        free(payload);
        bool ok = false;
        if (rc == PPC_OK) ok = registration_accepted(p, reply, reply_len);
        else if (rc == PPC_ERR_TIMEOUT)
            LOG_WARNING("%s: No registration response from manager within %g seconds (attempt %d).", p->opts.proxy_name, REGISTRATION_TIMEOUT, attempt);
        else if (rc != PPC_ERR_STOPPED)
            LOG_WARNING("%s: Error sending registration (attempt %d): %s", p->opts.proxy_name, attempt, ppc_strerror(rc));
        free(reply);
        if (ok) {
            p->registered = true;
            LOG_INFO("%s: Registered with manager @ %s:%d.", p->opts.proxy_name, p->opts.manager_address, p->opts.manager_port);
            return true;
        }
        if (rc == PPC_ERR_STOPPED) return false;
        if (attempt < REGISTRATION_ATTEMPTS) stoppable_sleep(p, REGISTRATION_RETRY_DELAY);
    }
    if (!atomic_load(&p->stop))
        LOG_ERROR("%s: Unable to register with Proxy Manager @ %s:%d after %d attempts. Stopping.", p->opts.proxy_name,
                  p->opts.manager_address, p->opts.manager_port, REGISTRATION_ATTEMPTS);
    return false;
}

int ppc_proxy_run(ppc_proxy *p) {
    if (p == NULL) return 1;
    signal_target = p;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigterm;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    int rc = ppc_connector_start(p->c);
    if (rc != PPC_OK) {
        LOG_ERROR("%s: unable to start the inbound listener: %s", p->opts.proxy_name, ppc_strerror(rc));
        return 1;
    }
    if (pthread_create(&p->watch_thread, NULL, watch_thread, p) != 0) {
        LOG_ERROR("%s: unable to start the manager watch thread.", p->opts.proxy_name);
        ppc_connector_stop(p->c);
        return 1;
    }
    p->watching = true;
    bool registered = send_registration(p);
    if (registered) {
        start_socket_logging(p);
        /* Serve until stopped: the watch thread stops the connector on SIGTERM, a lost parent or ppc_proxy_stop. */
        while (!atomic_load(&p->stop) && !ppc_connector_stopping(p->c)) stoppable_sleep(p, 0.5);
    }
    atomic_store(&p->stop, true);
    wake(p, 'x');
    pthread_join(p->watch_thread, NULL);
    p->watching = false;
    stop_socket_logging(p);
    ppc_connector_stop(p->c);
    signal_target = NULL;
    if (p->sigterm || p->manager_lost) return 0;
    return registered ? 0 : 1;
}
