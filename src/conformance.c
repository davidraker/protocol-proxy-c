/* The conformance harness (section 12) on the C manager: launch the proxy a manifest describes and check every
 * clause of the contract, by the same check names and in the same report layout as the Python
 * protocol-proxy-conformance command and the Go port's. */
#include "internal.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_TIMEOUT 20.0

/* Every record the manager handles for the proxy under test, and a forward to the caller's handler. The proxy is
 * launched at INFO so its switch to socket logging and SET_LOG_LEVEL's confirmation are shipped. */
typedef struct {
    pthread_mutex_t lock;
    ppc_record *records;
    size_t n, cap;
    ppc_record_fn forward;
    void *forward_user;
} capture;

typedef struct {
    ppc_manager *m;
    ppc_managed_proxy *p;
    double timeout;
    capture *cap;
} session;

static void capture_record(const ppc_record *r, void *user) {
    capture *c = user;
    pthread_mutex_lock(&c->lock);
    if (c->n == c->cap) {
        size_t cap = c->cap ? c->cap * 2 : 64;
        ppc_record *grown = realloc(c->records, cap * sizeof *grown);
        if (grown) { c->records = grown; c->cap = cap; }
    }
    if (c->n < c->cap && ppc_record_copy(r, &c->records[c->n]) == PPC_OK) c->n++;
    pthread_mutex_unlock(&c->lock);
    if (c->forward) c->forward(r, c->forward_user);
}

static size_t capture_count(capture *c, const char *channel, char *first, size_t first_len) {
    pthread_mutex_lock(&c->lock);
    size_t n = 0;
    for (size_t i = 0; i < c->n; i++) {
        if (strcmp(c->records[i].channel, channel) != 0) continue;
        if (n == 0 && first) snprintf(first, first_len, "%s", c->records[i].msg);
        n++;
    }
    pthread_mutex_unlock(&c->lock);
    return n;
}

static capture *capture_new(ppc_record_fn forward, void *user) {
    capture *c = calloc(1, sizeof *c);
    if (c == NULL) return NULL;
    pthread_mutex_init(&c->lock, NULL);
    c->forward = forward;
    c->forward_user = user;
    return c;
}

static void capture_free(capture *c) {
    if (c == NULL) return;
    for (size_t i = 0; i < c->n; i++) ppc_record_free(&c->records[i]);
    free(c->records);
    pthread_mutex_destroy(&c->lock);
    free(c);
}

/* ---- the report ----------------------------------------------------------------------------------------------- */
static void add(ppc_conformance_report *r, const char *name, bool passed, bool skipped, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));
static void add(ppc_conformance_report *r, const char *name, bool passed, bool skipped, const char *fmt, ...) {
    ppc_check *grown = realloc(r->checks, (r->n_checks + 1) * sizeof *grown);
    if (grown == NULL) return;
    r->checks = grown;
    ppc_check *c = &r->checks[r->n_checks];
    c->name = ppc_strdup(name);
    c->passed = passed || skipped;
    c->skipped = skipped;
    char detail[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof detail, fmt, ap);
    va_end(ap);
    c->detail = ppc_strdup(detail);
    r->n_checks++;
}

#define PASS(r, name, ok, ...) add((r), (name), (ok), false, __VA_ARGS__)
#define SKIP(r, name, ...) add((r), (name), true, true, __VA_ARGS__)

bool ppc_conformance_ok(const ppc_conformance_report *r) {
    for (size_t i = 0; i < r->n_checks; i++) if (!r->checks[i].passed && !r->checks[i].skipped) return false;
    return true;
}

static const char *status_of(const ppc_check *c) { return c->skipped ? "skip" : c->passed ? "pass" : "FAIL"; }

char *ppc_conformance_text(const ppc_conformance_report *r) {
    size_t width = 10;
    int passed = 0, failed = 0, skipped = 0;
    for (size_t i = 0; i < r->n_checks; i++) {
        size_t len = strlen(r->checks[i].name);
        if (len > width) width = len;
        if (r->checks[i].skipped) skipped++;
        else if (r->checks[i].passed) passed++;
        else failed++;
    }
    ppc_buf b = {0};
    char line[2048];
    snprintf(line, sizeof line, "%s: %s (%d passed, %d failed, %d skipped)\n", ppc_manifest_name(r->manifest),
             ppc_conformance_ok(r) ? "all checks pass" : "FAILURES", passed, failed, skipped);
    ppc_buf_append(&b, line, strlen(line));
    for (size_t i = 0; i < r->n_checks; i++) {
        snprintf(line, sizeof line, "  %-4s %-*s  %s\n", status_of(&r->checks[i]), (int)width, r->checks[i].name, r->checks[i].detail);
        ppc_buf_append(&b, line, strlen(line));
    }
    if (b.len) b.len--;                 /* no trailing newline, as the Python harness prints it */
    ppc_buf_append(&b, "", 1);
    return (char *)b.data;
}

char *ppc_conformance_json(const ppc_conformance_report *r) {
    ppc_json *o = ppc_json_new_object();
    if (o == NULL) return NULL;
    ppc_json_object_set(o, "proxy", ppc_json_new_string(ppc_manifest_name(r->manifest)));
    ppc_json_object_set(o, "ok", ppc_json_new_bool(ppc_conformance_ok(r)));
    ppc_json *features = ppc_json_new_array();
    for (size_t i = 0; i < r->n_features; i++) ppc_json_array_append(features, ppc_json_new_string(r->features[i]));
    ppc_json_object_set(o, "features", features);
    ppc_json *checks = ppc_json_new_array();
    for (size_t i = 0; i < r->n_checks; i++) {
        ppc_json *c = ppc_json_new_object();
        ppc_json_object_set(c, "name", ppc_json_new_string(r->checks[i].name));
        ppc_json_object_set(c, "status", ppc_json_new_string(status_of(&r->checks[i])));
        ppc_json_object_set(c, "detail", ppc_json_new_string(r->checks[i].detail));
        ppc_json_array_append(checks, c);
    }
    ppc_json_object_set(o, "checks", checks);
    char *text = ppc_json_dump(o);
    ppc_json_free(o);
    return text;
}

void ppc_conformance_report_free(ppc_conformance_report *r) {
    if (r == NULL) return;
    for (size_t i = 0; i < r->n_checks; i++) { free(r->checks[i].name); free(r->checks[i].detail); }
    free(r->checks);
    ppc_strings_free(r->features, r->n_features);
    free(r);
}

/* ---- sessions ------------------------------------------------------------------------------------------------- */
static char *py_list(char **items, size_t n) {
    ppc_buf b = {0};
    ppc_buf_append(&b, "[", 1);
    for (size_t i = 0; i < n; i++) {
        if (i) ppc_buf_append(&b, ", ", 2);
        ppc_buf_append(&b, "'", 1);
        ppc_buf_append(&b, items[i], strlen(items[i]));
        ppc_buf_append(&b, "'", 1);
    }
    ppc_buf_append(&b, "]", 2);
    return (char *)b.data;
}

static bool has_feature(char **features, size_t n, const char *name) {
    for (size_t i = 0; i < n; i++) if (strcmp(features[i], name) == 0) return true;
    return false;
}

static int request(session *s, const char *method, const char *payload, size_t len, int version, uint8_t **reply, size_t *reply_len) {
    ppc_message m = {method, (const uint8_t *)payload, len, true, NULL, version, false};
    return ppc_manager_request(s->m, s->p, &m, s->timeout, reply, reply_len);
}

/* A request whose reply is JSON: *out receives the parsed reply (NULL for an empty one); err_text describes a
 * failure. */
static int request_json(session *s, const char *method, const char *payload, int version, ppc_json **out, char *err_text, size_t err_len) {
    *out = NULL;
    uint8_t *reply = NULL;
    size_t reply_len = 0;
    int rc = request(s, method, payload, payload ? strlen(payload) : 0, version, &reply, &reply_len);
    if (rc != PPC_OK) { snprintf(err_text, err_len, "request failed: %s", ppc_strerror(rc)); free(reply); return rc; }
    if (reply_len == 0) { free(reply); return PPC_OK; }
    char perr[64];
    *out = ppc_json_parse((const char *)reply, reply_len, perr, sizeof perr);
    if (*out == NULL) { snprintf(err_text, err_len, "reply is not JSON: %.*s", (int)(reply_len > 200 ? 200 : reply_len), (const char *)reply); free(reply); return PPC_ERR_INVALID; }
    free(reply);
    return PPC_OK;
}

static char *detail_of(const ppc_json *v) {
    char *text = v ? ppc_json_dump(v) : ppc_strdup("None");
    return text ? text : ppc_strdup("?");
}

static bool is_health(const ppc_json *v) {
    if (v == NULL || v->type != PPC_JSON_OBJECT) return false;
    const ppc_json *uptime = ppc_json_get(v, "uptime"), *remotes = ppc_json_get(v, "remotes"), *busy = ppc_json_get(v, "busy");
    return uptime && uptime->type == PPC_JSON_NUMBER && remotes && remotes->type == PPC_JSON_NUMBER && busy && busy->type == PPC_JSON_BOOL
           && ppc_json_get(v, "last_activity") != NULL;
}

static bool has_uptime(const ppc_json *v) { return v && v->type == PPC_JSON_OBJECT && ppc_json_get(v, "uptime") != NULL; }

/* Stop the manager (SIGTERM to the proxy) and record the exit code check. */
static void exit_check(ppc_conformance_report *r, session *s, const char *name) {
    ppc_manager_stop(s->m, true, 5.0);
    int code = 0;
    if (ppc_managed_proxy_wait(s->p, 10.0, &code)) PASS(r, name, code == 0, "exit code %d", code);
    else PASS(r, name, false, "exit code None");
}

static void session_close(session *s) {
    if (s == NULL) return;
    ppc_manager_free(s->m);
    capture_free(s->cap);
    free(s);
}

static char *echo_payload(const char *prefix, char fill, size_t count, const char *suffix, size_t *len) {
    size_t n = strlen(prefix) + count + strlen(suffix);
    char *out = malloc(n + 1);
    if (out == NULL) return NULL;
    memcpy(out, prefix, strlen(prefix));
    memset(out + strlen(prefix), fill, count);
    memcpy(out + strlen(prefix) + count, suffix, strlen(suffix) + 1);
    *len = n;
    return out;
}

/* Round-trip each payload through the echo method; an error text in err on failure. */
static bool echo(session *s, const char *method, const char *const *payloads, const size_t *lens, size_t n, char *err, size_t err_len) {
    for (size_t i = 0; i < n; i++) {
        uint8_t *reply = NULL;
        size_t reply_len = 0;
        int rc = request(s, method, payloads[i], lens[i], 2, &reply, &reply_len);
        if (rc != PPC_OK) { snprintf(err, err_len, "request failed: %s", ppc_strerror(rc)); free(reply); return false; }
        bool same = reply_len == lens[i] && (lens[i] == 0 || memcmp(reply, payloads[i], lens[i]) == 0);
        free(reply);
        if (!same) { snprintf(err, err_len, "echo of %zu bytes came back as %zu bytes", lens[i], reply_len); return false; }
    }
    return true;
}

static int free_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int port = 0;
    socklen_t sl = sizeof sa;
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0 && getsockname(fd, (struct sockaddr *)&sa, &sl) == 0) port = ntohs(sa.sin_port);
    close(fd);
    return port;
}

typedef struct {
    const ppc_manifest *manifest;
    const ppc_conformance_options *opts;
    ppc_conformance_report *report;
} run_state;

/* Launch a session with a manager configured by cfg (encrypt, cipher, ipc_tls) plus the launch options; records the
 * registration check and returns NULL when the proxy did not register. */
static session *open_session(run_state *st, const char *name, bool encrypt, const char *cipher, bool ipc_tls,
                             const ppc_option *launch, size_t n_launch) {
    ppc_conformance_report *r = st->report;
    double timeout = st->opts->timeout > 0 ? st->opts->timeout : DEFAULT_TIMEOUT;
    capture *cap = capture_new(st->opts->records, st->opts->records_user);
    if (cap == NULL) { PASS(r, name, false, "out of memory"); return NULL; }
    ppc_manager_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.manifest = st->manifest;
    cfg.encrypt = encrypt;
    cfg.cipher = cipher;
    cfg.ipc_tls = ipc_tls;
    cfg.heartbeat_interval = -1;
    cfg.python = st->opts->python;
    cfg.records = capture_record;
    cfg.records_user = cap;
    cfg.proxy_log_level = PPC_LOG_INFO;
    char err[512];
    char check[128];
    snprintf(check, sizeof check, "%s: registration", name);
    ppc_manager *m = ppc_manager_new(&cfg, err, sizeof err);
    int rc = m ? ppc_manager_start(m) : PPC_ERR_IO;
    if (rc != PPC_OK) {
        PASS(r, check, false, "manager: %s", m ? ppc_strerror(rc) : err);
        ppc_manager_free(m);
        capture_free(cap);
        return NULL;
    }
    size_t n = st->opts->n_launch_options + n_launch;
    ppc_option *options = calloc(n + 1, sizeof *options);
    size_t k = 0;
    for (size_t i = 0; options && i < st->opts->n_launch_options; i++) options[k++] = st->opts->launch_options[i];
    for (size_t i = 0; options && i < n_launch; i++) options[k++] = launch[i];
    session *s = calloc(1, sizeof *s);
    const char *remote[1] = {"conformance"};
    ppc_managed_proxy *p = options && s ? ppc_manager_get_proxy(m, remote, 1, options, k, err, sizeof err) : NULL;
    free(options);
    if (p == NULL) {
        PASS(r, check, false, "%s", err[0] ? err : "out of memory");
        ppc_manager_free(m);
        capture_free(cap);
        free(s);
        return NULL;
    }
    s->m = m;
    s->p = p;
    s->timeout = timeout;
    s->cap = cap;
    if (ppc_manager_wait_registered(m, p, timeout) != PPC_OK) {
        PASS(r, check, false, "no registration within %gs", timeout);
        session_close(s);
        return NULL;
    }
    size_t nf = 0;
    char **features = ppc_peer_features(ppc_managed_proxy_peer(p), &nf);
    char *list = py_list(features, nf);
    PASS(r, check, true, "features %s", list ? list : "[]");
    free(list);
    ppc_strings_free(features, nf);
    return s;
}

ppc_conformance_report *ppc_conformance_run(const ppc_manifest *manifest, const ppc_conformance_options *options) {
    static const ppc_conformance_options none = {0};
    if (options == NULL) options = &none;
    ppc_conformance_report *r = calloc(1, sizeof *r);
    if (r == NULL) return NULL;
    r->manifest = manifest;
    run_state st = {manifest, options, r};
    const char *echo_method = options->echo_method && options->echo_method[0] ? options->echo_method : NULL;
    char err_text[512];
    ppc_json *v = NULL;
    char *text;

    /* ---- 1. per-message connections: the core contract ---------------------------------------------------- */
    ppc_option per_message[] = {{"persistent", "false"}};
    session *s = open_session(&st, "per-message", false, NULL, false, per_message, 1);
    if (s) {
        r->features = ppc_peer_features(ppc_managed_proxy_peer(s->p), &r->n_features);
        if (request_json(s, "PING", NULL, 2, &v, err_text, sizeof err_text) != PPC_OK) PASS(r, "ping reply", false, "%s", err_text);
        else { text = detail_of(v); PASS(r, "ping reply", is_health(v), "%s", text); free(text); }
        ppc_json_free(v);
        if (request_json(s, "NO_SUCH_METHOD_CONFORMANCE", "{\"x\": 1}", 2, &v, err_text, sizeof err_text) != PPC_OK)
            PASS(r, "unknown method answered with an error reply", false, "%s", err_text);
        else {
            bool ok = v && v->type == PPC_JSON_OBJECT && strcmp(ppc_json_get_string(v, "status", ""), "error") == 0
                      && ppc_json_get(v, "method") && ppc_json_get(v, "error");
            text = detail_of(v);
            PASS(r, "unknown method answered with an error reply", ok, "%s", text);
            free(text);
        }
        ppc_json_free(v);
        if (has_feature(r->features, r->n_features, "set_log_level")) {
            if (request_json(s, "SET_LOG_LEVEL", "{\"level\": \"DEBUG\"}", 2, &v, err_text, sizeof err_text) != PPC_OK) PASS(r, "SET_LOG_LEVEL", false, "%s", err_text);
            else {
                text = detail_of(v);
                PASS(r, "SET_LOG_LEVEL", v && strcmp(ppc_json_get_string(v, "level", ""), "DEBUG") == 0, "%s", text);
                free(text);
                ppc_json_free(v);
                request_json(s, "SET_LOG_LEVEL", "{\"level\": \"INFO\"}", 2, &v, err_text, sizeof err_text);
            }
            ppc_json_free(v);
        } else {
            SKIP(r, "SET_LOG_LEVEL", "not advertised");
        }
        if (has_feature(r->features, r->n_features, "log")) {
            /* The proxy has had something to say since it registered (its switch to the socket, SET_LOG_LEVEL's
             * confirmation), so a batch must have been shipped by now or very soon. */
            double deadline = ppc_monotonic() + PPC_CONFORMANCE_LOG_BATCH_WAIT;
            char first[512] = "";
            size_t n = 0;
            while ((n = capture_count(s->cap, "socket", first, sizeof first)) == 0 && ppc_monotonic() < deadline) {
                struct timespec ts = {0, 50000000L};
                nanosleep(&ts, NULL);
            }
            if (n) PASS(r, "LOG batch over the socket", true, "%zu record(s), first: \"%s\"", n, first);
            else PASS(r, "LOG batch over the socket", false, "no record over the socket within %gs (%zu by stderr)",
                      PPC_CONFORMANCE_LOG_BATCH_WAIT, capture_count(s->cap, "stderr", NULL, 0));
        } else {
            SKIP(r, "LOG batch over the socket", "not advertised");
        }
        if (request_json(s, "PING", NULL, 1, &v, err_text, sizeof err_text) != PPC_OK) PASS(r, "header version 1 accepted", false, "%s", err_text);
        else { text = detail_of(v); PASS(r, "header version 1 accepted", has_uptime(v), "%s", text); free(text); }
        ppc_json_free(v);
        if (echo_method) {
            const char *small = "{\"n\": 1, \"text\": \"h\\u00e9llo\"}";
            size_t large_len = 0;
            char *large = echo_payload("{\"blob\": \"", 'x', 65536, "\"}", &large_len);
            const char *payloads[2] = {small, large};
            size_t lens[2] = {strlen(small), large_len};
            if (echo(s, echo_method, payloads, lens, 2, err_text, sizeof err_text))
                PASS(r, "echo round trip, small and 64 KiB", true, "%s", has_feature(r->features, r->n_features, "compress") ? "compressed on the wire" : "uncompressed (compress not advertised)");
            else PASS(r, "echo round trip, small and 64 KiB", false, "%s", err_text);
            free(large);
        } else {
            SKIP(r, "echo round trip, small and 64 KiB", "no echo method given");
        }
        exit_check(r, s, "clean exit on SIGTERM");
        session_close(s);
    }

    /* ---- 2. persistent connection ------------------------------------------------------------------------- */
    ppc_option persistent[] = {{"persistent", "true"}};
    s = open_session(&st, "persistent", false, NULL, false, persistent, 1);
    if (s) {
        bool ok = true;
        char last[512] = "";
        for (int i = 0; i < 5 && ok; i++) {
            if (request_json(s, "PING", NULL, 2, &v, err_text, sizeof err_text) != PPC_OK) { ok = false; snprintf(last, sizeof last, "%s", err_text); }
            else if (!has_uptime(v)) { ok = false; text = detail_of(v); snprintf(last, sizeof last, "%s", text); free(text); }
            ppc_json_free(v);
            v = NULL;
        }
        if (ok && !ppc_peer_linked(ppc_managed_proxy_peer(s->p))) { ok = false; snprintf(last, sizeof last, "no persistent connection held"); }
        PASS(r, "persistent: five pings on one connection", ok, "%s", ok ? "connection held" : last);
        if (echo_method) {
            size_t large_len = 0;
            char *large = echo_payload("{\"blob\": \"", 'y', 300000, "\"}", &large_len);   /* above persistent_max_frame */
            const char *payloads[1] = {large};
            if (echo(s, echo_method, payloads, &large_len, 1, err_text, sizeof err_text)) PASS(r, "persistent: 300 KB frame takes its own connection", true, "%s", "");
            else PASS(r, "persistent: 300 KB frame takes its own connection", false, "%s", err_text);
            free(large);
        }
        exit_check(r, s, "persistent: clean exit on SIGTERM");
        session_close(s);
    }

    /* ---- 3. encryption, each AEAD the proxy advertises ---------------------------------------------------- */
    const char *ciphers[2][2] = {{"chacha20-poly1305", "aead-chacha20poly1305"}, {"aes-256-gcm", "aead-aes256gcm"}};
    for (int c = 0; c < 2; c++) {
        char name[64];
        snprintf(name, sizeof name, "encrypted (%s)", ciphers[c][0]);
        if (!has_feature(r->features, r->n_features, ciphers[c][1])) { SKIP(r, name, "%s not advertised", ciphers[c][1]); continue; }
        s = open_session(&st, name, true, ciphers[c][0], false, persistent, 1);
        if (s == NULL) continue;
        char check[128];
        snprintf(check, sizeof check, "%s: ping", name);
        if (request_json(s, "PING", NULL, 2, &v, err_text, sizeof err_text) != PPC_OK) PASS(r, check, false, "%s", err_text);
        else {
            text = detail_of(v);
            PASS(r, check, has_uptime(v) && ppc_peer_has_key(ppc_managed_proxy_peer(s->p)), "%s", text);
            free(text);
            if (echo_method) {
                size_t large_len = 0;
                char *large = echo_payload("{\"blob\": \"", 'z', 65536, "\"}", &large_len);
                const char *payloads[1] = {large};
                bool ok = echo(s, echo_method, payloads, &large_len, 1, err_text, sizeof err_text);
                snprintf(check, sizeof check, "%s: 64 KiB echo (compress then encrypt)", name);
                PASS(r, check, ok, "%s", ok ? "" : err_text);
                free(large);
            }
        }
        ppc_json_free(v);
        v = NULL;
        snprintf(check, sizeof check, "%s: clean exit", name);
        exit_check(r, s, check);
        session_close(s);
    }

    /* ---- 4. optional transports ----------------------------------------------------------------------------- */
    if (options->tls) {
        s = open_session(&st, "tls", false, NULL, true, persistent, 1);
        if (s) {
            if (request_json(s, "PING", NULL, 2, &v, err_text, sizeof err_text) != PPC_OK) PASS(r, "tls: ping", false, "%s", err_text);
            else { text = detail_of(v); PASS(r, "tls: ping", has_uptime(v) && ppc_peer_tls(ppc_managed_proxy_peer(s->p)), "%s", text); free(text); }
            ppc_json_free(v);
            v = NULL;
            exit_check(r, s, "tls: clean exit");
            session_close(s);
        }
    } else {
        SKIP(r, "tls", "not requested (--tls)");
    }
    if (options->manager_dials) {
        int port = free_port();
        char port_text[16];
        snprintf(port_text, sizeof port_text, "%d", port);
        ppc_option dials[] = {{"manager_dials", "true"}, {"inbound_address", "127.0.0.1"}, {"inbound_port", port_text}};
        if (port == 0) PASS(r, "manager-dials: registration", false, "no free port");
        else if ((s = open_session(&st, "manager-dials", false, NULL, false, dials, 3)) != NULL) {
            if (request_json(s, "PING", NULL, 2, &v, err_text, sizeof err_text) != PPC_OK) PASS(r, "manager-dials: ping over the manager-initiated connection", false, "%s", err_text);
            else { text = detail_of(v); PASS(r, "manager-dials: ping over the manager-initiated connection", has_uptime(v), "%s", text); free(text); }
            ppc_json_free(v);
            v = NULL;
            exit_check(r, s, "manager-dials: clean exit");
            session_close(s);
        }
    } else {
        SKIP(r, "manager-dials", "not requested (--manager-dials)");
    }
    return r;
}
