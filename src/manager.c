/* The ProtocolProxyManager (sections 1, 1a, 7, 9, 10, 11b): launches the proxy processes a manifest describes,
 * hands each its tokens, key and TLS material on stdin, accepts their registration, reads their logs from the pipes
 * and from LOG batches, keeps them alive with PING, terminates them on stop and relaunches them on the next request
 * after a loss. Built on the same connector as a proxy, so a C program can host proxies written in any language.
 *
 * Threads: one watcher and two pipe readers per launched process, one dialler per manager-dials proxy until it
 * registers, one heartbeat thread, and one terminator per lost proxy that is still running. Every thread is joined
 * when the manager is freed; they all poll with short timeouts so a free never waits long. */
#include "internal.h"

#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define DIAL_RETRY_INTERVAL 1.0
#define POLL_STEP_MS 20
#define READ_CHUNK 65536
#define MAX_LINE (16u * 1024u * 1024u)

static const char *const MANAGER_FEATURES[] = {"compress", "aead-chacha20poly1305", "aead-aes256gcm"};
static const char *const MANAGER_ONLY_OPTIONS[] = {"manager_callbacks", "dial", "ssh_host", "ssh_options", "ssh_forward",
                                                   "remote_python", "remote_env"};

typedef struct lost_cb {
    ppc_lost_fn fn;
    void *user;
    struct lost_cb *next;
} lost_cb;

/* One process key: its proxy id (kept across relaunches) and the must_match options of its first remote. */
typedef struct key_entry {
    char *key;
    ppc_uuid id;
    ppc_option *shared;
    size_t n_shared;
    struct key_entry *next;
} key_entry;

struct ppc_managed_proxy {
    ppc_manager *m;
    ppc_uuid id, token;
    char *name;
    char *logger_name;
    ppc_json *key;
    char **command;
    size_t argc;
    ppc_peer *peer;
    bool has_key;
    uint8_t aead_key[PPC_KEY_BYTES];
    bool tls;
    ppc_tls_material *material;
    char *dial_address;
    int dial_port;
    atomic_bool current;
    /* the process */
    pid_t pid;
    atomic_bool launched, exited;
    int exit_code;
    int out_fd, err_fd;
    pthread_t watch_thread, out_thread, err_thread, dial_thread, term_thread;
    bool has_watch, has_out, has_err, has_dial, has_term;
    atomic_bool terminating;
    /* liveness, under m->lock */
    const char *state;
    atomic_bool registered;
    double last_seen;
    int missed;
    ppc_json *health;
    atomic_int log_level;
    char *cipher;
    char *lost_reason;
    struct ppc_managed_proxy *next;
};

struct ppc_manager {
    const ppc_manifest *manifest;
    ppc_uuid token;                     /* the connector's token, written to every proxy's stdin */
    char *name;
    char *inbound_address;
    int inbound_port;
    bool persistent, encrypt, ipc_tls;
    long compress_threshold;
    double heartbeat_interval, heartbeat_timeout;
    int heartbeat_misses;
    bool heartbeat_enabled;
    char *python;
    char **env_names, **env_values;
    size_t n_env;
    ppc_record_fn records;
    void *records_user;
    int proxy_log_level;

    ppc_connector *c;
    ppc_authority *authority;
    ppc_tls_material *material;

    pthread_mutex_t lock;
    pthread_cond_t cond;
    ppc_managed_proxy *all;             /* every proxy ever created, newest first */
    key_entry *keys;
    lost_cb *lost;
    pthread_t heartbeat_thread;
    bool heartbeating;
    atomic_bool stopped, freeing;
    bool started;
};

typedef struct {
    ppc_managed_proxy *p;
    int fd;
    const char *stream;
} reader_arg;

static void set_err(char *err, size_t err_len, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void set_err(char *err, size_t err_len, const char *fmt, ...) {
    if (err == NULL || err_len == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, err_len, fmt, ap);
    va_end(ap);
}

static void sleep_ms(int ms) {
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static void deadline_after(struct timespec *ts, double seconds) {
    clock_gettime(CLOCK_MONOTONIC, ts);
    ts->tv_sec += (time_t)seconds;
    ts->tv_nsec += (long)((seconds - (double)(time_t)seconds) * 1e9);
    if (ts->tv_nsec >= 1000000000L) { ts->tv_sec++; ts->tv_nsec -= 1000000000L; }
}

/* ---- construction --------------------------------------------------------------------------------------------- */
static int handle_register_peer(ppc_connector *c, const ppc_header *h, const uint8_t *payload, size_t len,
                                uint8_t **reply, size_t *reply_len, void *user);
static int handle_log(ppc_connector *c, const ppc_header *h, const uint8_t *payload, size_t len, uint8_t **reply,
                      size_t *reply_len, void *user);

ppc_manager *ppc_manager_new(const ppc_manager_config *cfg, char *err, size_t err_len) {
    if (err && err_len) err[0] = '\0';
    if (cfg == NULL || cfg->manifest == NULL) { set_err(err, err_len, "a manager needs a manifest"); return NULL; }
    const char *cipher = ppc_resolve_cipher(cfg->cipher);
    if (cipher == NULL) { set_err(err, err_len, "unknown cipher %s", cfg->cipher); return NULL; }
    ppc_manager *m = calloc(1, sizeof *m);
    if (m == NULL) return NULL;
    m->manifest = cfg->manifest;
    m->name = ppc_strdup(cfg->name ? cfg->name : "Manager");
    m->inbound_address = ppc_strdup(cfg->inbound_address ? cfg->inbound_address : "localhost");
    m->inbound_port = cfg->inbound_port;
    m->persistent = cfg->persistent;
    m->encrypt = cfg->encrypt;
    m->ipc_tls = cfg->ipc_tls;
    m->compress_threshold = cfg->compress_threshold;
    m->heartbeat_enabled = cfg->heartbeat_interval >= 0;
    m->heartbeat_interval = cfg->heartbeat_interval > 0 ? cfg->heartbeat_interval : PPC_MANAGER_HEARTBEAT_INTERVAL;
    m->heartbeat_timeout = cfg->heartbeat_timeout > 0 ? cfg->heartbeat_timeout : PPC_MANAGER_HEARTBEAT_TIMEOUT;
    m->heartbeat_misses = cfg->heartbeat_misses > 0 ? cfg->heartbeat_misses : PPC_MANAGER_HEARTBEAT_MISSES;
    m->python = cfg->python ? ppc_strdup(cfg->python) : NULL;
    m->records = cfg->records ? cfg->records : ppc_record_log;
    m->records_user = cfg->records_user;
    m->proxy_log_level = cfg->proxy_log_level > 0 ? cfg->proxy_log_level : PPC_LOG_INFO;
    if (cfg->env_count) {
        m->env_names = calloc(cfg->env_count, sizeof *m->env_names);
        m->env_values = calloc(cfg->env_count, sizeof *m->env_values);
        for (size_t i = 0; m->env_names && m->env_values && i < cfg->env_count; i++) {
            m->env_names[i] = ppc_strdup(cfg->env_names[i]);
            m->env_values[i] = ppc_strdup(cfg->env_values[i]);
            m->n_env++;
        }
    }
    pthread_mutex_init(&m->lock, NULL);
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&m->cond, &attr);
    pthread_condattr_destroy(&attr);
    atomic_init(&m->stopped, false);
    atomic_init(&m->freeing, false);
    if (m->name == NULL || m->inbound_address == NULL) { ppc_manager_free(m); return NULL; }

    ppc_uuid id, token;
    if (ppc_uuid_random(&id) != PPC_OK || ppc_uuid_random(&token) != PPC_OK) { ppc_manager_free(m); return NULL; }
    char id_text[37];
    ppc_uuid_str(&id, id_text);
    char ca_name[80];
    snprintf(ca_name, sizeof ca_name, "protocol-proxy manager %s", id_text);
    m->authority = ppc_authority_new(ca_name, err, err_len);
    if (m->authority == NULL) { ppc_manager_free(m); return NULL; }
    char hex[33];
    ppc_uuid_hex(&id, hex);
    const char *addresses[1] = {m->inbound_address};
    m->material = ppc_authority_issue(m->authority, hex, addresses, 1, err, err_len);
    if (m->material == NULL) { ppc_manager_free(m); return NULL; }

    ppc_connector_config cc;
    memset(&cc, 0, sizeof cc);
    m->token = token;
    cc.proxy_id = id;
    cc.token = token;
    cc.proxy_name = m->name;
    cc.inbound_address = m->inbound_address;
    cc.inbound_port = m->inbound_port;
    cc.persistent = m->persistent;
    cc.compress_threshold = m->compress_threshold;
    cc.cipher = cipher;
    cc.tls = m->material;
    cc.tls_accept_plain = true;             /* plain and TLS proxies share the one listener */
    m->c = ppc_connector_new(&cc);
    if (m->c == NULL) { set_err(err, err_len, "unable to create the manager's connector"); ppc_manager_free(m); return NULL; }
    ppc_connector_register_handler(m->c, "REGISTER_PEER", NULL, handle_register_peer, m, true);
    ppc_connector_register_handler(m->c, "LOG", NULL, handle_log, m, false);
    return m;
}

ppc_connector *ppc_manager_connector(ppc_manager *m) { return m->c; }
const ppc_uuid *ppc_manager_id(const ppc_manager *m) { return ppc_connector_id(m->c); }
const char *ppc_manager_cipher(const ppc_manager *m) { return ppc_connector_cipher(m->c); }
bool ppc_manager_stopped(const ppc_manager *m) { return atomic_load(&m->stopped); }

const char *ppc_manager_python(const ppc_manager *m) {
    if (m->python && *m->python) return m->python;
    const char *env = getenv(PPC_PYTHON_ENV);
    return env && *env ? env : "python3";
}

int ppc_manager_local_address(ppc_manager *m, char *address, size_t address_len, int *port) {
    return ppc_connector_local_address(m->c, address, address_len, port);
}

/* ---- proxies: lookup and state -------------------------------------------------------------------------------- */
static ppc_managed_proxy *find_current_locked(ppc_manager *m, const ppc_uuid *id) {
    for (ppc_managed_proxy *p = m->all; p; p = p->next)
        if (atomic_load(&p->current) && ppc_uuid_equal(&p->id, id)) return p;
    return NULL;
}

ppc_managed_proxy *ppc_manager_proxy_by_id(ppc_manager *m, const ppc_uuid *id) {
    pthread_mutex_lock(&m->lock);
    ppc_managed_proxy *p = find_current_locked(m, id);
    pthread_mutex_unlock(&m->lock);
    return p;
}

ppc_managed_proxy **ppc_manager_proxies(ppc_manager *m, size_t *count) {
    pthread_mutex_lock(&m->lock);
    size_t n = 0;
    for (ppc_managed_proxy *p = m->all; p; p = p->next) if (atomic_load(&p->current)) n++;
    ppc_managed_proxy **out = calloc(n + 1, sizeof *out);
    size_t i = 0;
    for (ppc_managed_proxy *p = m->all; out && p; p = p->next) if (atomic_load(&p->current)) out[i++] = p;
    pthread_mutex_unlock(&m->lock);
    if (count) *count = out ? n : 0;
    return out;
}

ppc_peer *ppc_managed_proxy_peer(ppc_managed_proxy *p) { return p->peer; }
const ppc_uuid *ppc_managed_proxy_id(const ppc_managed_proxy *p) { return &p->id; }
const char *ppc_managed_proxy_name(const ppc_managed_proxy *p) { return p->name; }
const ppc_json *ppc_managed_proxy_key(const ppc_managed_proxy *p) { return p->key; }
bool ppc_managed_proxy_registered(ppc_managed_proxy *p) { return atomic_load(&p->registered); }
bool ppc_managed_proxy_lost(ppc_managed_proxy *p) { return !atomic_load(&p->current); }
int ppc_managed_proxy_log_level(ppc_managed_proxy *p) { return atomic_load(&p->log_level); }
pid_t ppc_managed_proxy_pid(ppc_managed_proxy *p) { return atomic_load(&p->launched) ? p->pid : 0; }
bool ppc_managed_proxy_running(ppc_managed_proxy *p) { return atomic_load(&p->launched) && !atomic_load(&p->exited); }

size_t ppc_managed_proxy_command(const ppc_managed_proxy *p, const char *const **argv) {
    if (argv) *argv = (const char *const *)p->command;
    return p->argc;
}

const char *ppc_managed_proxy_state(ppc_managed_proxy *p) {
    pthread_mutex_lock(&p->m->lock);
    const char *s = p->state;
    pthread_mutex_unlock(&p->m->lock);
    return s;
}

const char *ppc_managed_proxy_lost_reason(ppc_managed_proxy *p) {
    pthread_mutex_lock(&p->m->lock);
    const char *s = p->lost_reason;
    pthread_mutex_unlock(&p->m->lock);
    return s;
}

const char *ppc_managed_proxy_cipher(ppc_managed_proxy *p) {
    pthread_mutex_lock(&p->m->lock);
    const char *s = p->cipher;
    pthread_mutex_unlock(&p->m->lock);
    return s;
}

char *ppc_managed_proxy_health_json(ppc_managed_proxy *p) {
    pthread_mutex_lock(&p->m->lock);
    char *text = p->health ? ppc_json_dump(p->health) : NULL;
    pthread_mutex_unlock(&p->m->lock);
    return text;
}

bool ppc_managed_proxy_wait(ppc_managed_proxy *p, double timeout, int *code) {
    double deadline = ppc_monotonic() + timeout;
    while (!atomic_load(&p->exited) && ppc_monotonic() < deadline) sleep_ms(POLL_STEP_MS);
    if (!atomic_load(&p->exited)) return false;
    if (code) *code = p->exit_code;
    return true;
}

static void proxy_free(ppc_managed_proxy *p) {
    if (p == NULL) return;
    free(p->name);
    free(p->logger_name);
    ppc_json_free(p->key);
    ppc_strings_free(p->command, p->argc);
    ppc_tls_material_free(p->material);
    free(p->dial_address);
    ppc_json_free(p->health);
    free(p->cipher);
    free(p->lost_reason);
    memset(p->aead_key, 0, sizeof p->aead_key);
    free(p);
}

/* ---- losing a proxy ------------------------------------------------------------------------------------------- */
static void *terminate_thread(void *arg);

/* Stop a proxy's process: SIGTERM, then SIGKILL after timeout. While it runs the process is not pinged. */
static void terminate(ppc_manager *m, ppc_managed_proxy *p, double timeout) {
    if (!ppc_managed_proxy_running(p)) return;
    atomic_store(&p->terminating, true);
    LOG_INFO("Terminating %s with PID: %d", ppc_manifest_name(m->manifest), (int)p->pid);
    if (kill(p->pid, SIGTERM) != 0 && errno != ESRCH)
        LOG_WARNING("Exception encountered attempting to terminate proxy process (%d): %s", (int)p->pid, strerror(errno));
    if (!ppc_managed_proxy_wait(p, timeout, NULL)) {
        LOG_INFO("Killing %s with PID: %d", ppc_manifest_name(m->manifest), (int)p->pid);
        kill(p->pid, SIGKILL);
        if (!ppc_managed_proxy_wait(p, timeout, NULL))
            LOG_WARNING("Failed to stop %s with PID: %d", ppc_manifest_name(m->manifest), (int)p->pid);
    }
    atomic_store(&p->terminating, false);
}

static void *terminate_thread(void *arg) {
    ppc_managed_proxy *p = arg;
    terminate(p->m, p, PPC_MANAGER_TERMINATE_TIMEOUT);
    return NULL;
}

void ppc_manager_terminate(ppc_manager *m, ppc_managed_proxy *p, double timeout) {
    terminate(m, p, timeout > 0 ? timeout : PPC_MANAGER_TERMINATE_TIMEOUT);
}

/* Forget a proxy, stop its process if it still runs, and tell the listeners. */
static void lose(ppc_manager *m, ppc_managed_proxy *p, const char *reason) {
    pthread_mutex_lock(&m->lock);
    if (!atomic_load(&p->current)) { pthread_mutex_unlock(&m->lock); return; }
    atomic_store(&p->current, false);
    p->state = "lost";
    free(p->lost_reason);
    p->lost_reason = ppc_strdup(reason);
    ppc_connector_remove_peer(m->c, &p->id);        /* under m->lock, so a relaunch never finds the old peer */
    pthread_cond_broadcast(&m->cond);
    size_t n = 0;
    for (lost_cb *cb = m->lost; cb; cb = cb->next) n++;
    lost_cb *copies = n ? calloc(n, sizeof *copies) : NULL;
    size_t i = 0;
    for (lost_cb *cb = m->lost; copies && cb; cb = cb->next) copies[i++] = *cb;
    if (ppc_managed_proxy_running(p) && !p->has_term && !atomic_load(&m->freeing)) {
        if (pthread_create(&p->term_thread, NULL, terminate_thread, p) == 0) p->has_term = true;
    }
    pthread_mutex_unlock(&m->lock);
    for (size_t k = 0; copies && k < n; k++) copies[k].fn(m, p, reason, copies[k].user);
    free(copies);
}

void ppc_manager_on_proxy_lost(ppc_manager *m, ppc_lost_fn fn, void *user) {
    if (m == NULL || fn == NULL) return;
    lost_cb *cb = calloc(1, sizeof *cb);
    if (cb == NULL) return;
    cb->fn = fn;
    cb->user = user;
    pthread_mutex_lock(&m->lock);
    cb->next = m->lost;
    m->lost = cb;
    pthread_mutex_unlock(&m->lock);
}

/* ---- the process: pipes, watcher ------------------------------------------------------------------------------ */
static void emit_record(ppc_managed_proxy *p, ppc_record *r) {
    if (r->level >= atomic_load(&p->log_level)) p->m->records(r, p->m->records_user);
    ppc_record_free(r);
}

static void handle_line(ppc_managed_proxy *p, const char *stream, const char *line, size_t len) {
    ppc_record r;
    if (ppc_record_from_line(line, len, p->logger_name, stream, (int)p->pid, p->name, &r) == 1) emit_record(p, &r);
}

/* Read a pipe to EOF, one record per line (section 9). Polls so the manager's free is never held up. */
static void *reader_thread(void *arg) {
    reader_arg *ra = arg;
    ppc_managed_proxy *p = ra->p;
    ppc_buf buf = {0};
    uint8_t *chunk = malloc(READ_CHUNK);
    struct pollfd pfd = {ra->fd, POLLIN, 0};
    while (chunk && !atomic_load(&p->m->freeing)) {
        int n = poll(&pfd, 1, 100);
        if (n < 0 && errno != EINTR) break;
        if (n <= 0) continue;
        ssize_t got = read(ra->fd, chunk, READ_CHUNK);
        if (got < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (got <= 0) break;
        ppc_buf_append(&buf, chunk, (size_t)got);
        size_t start = 0;
        for (size_t i = 0; i < buf.len; i++) {
            if (buf.data[i] != '\n') continue;
            handle_line(p, ra->stream, (const char *)buf.data + start, i - start);
            start = i + 1;
        }
        if (start) { memmove(buf.data, buf.data + start, buf.len - start); buf.len -= start; }
        if (buf.len > MAX_LINE) { handle_line(p, ra->stream, (const char *)buf.data, buf.len); buf.len = 0; }
    }
    if (buf.len) handle_line(p, ra->stream, (const char *)buf.data, buf.len);
    ppc_buf_free(&buf);
    free(chunk);
    close(ra->fd);
    free(ra);
    return NULL;
}

/* Reap the process; when it exits, drop the proxy if it is still the current one for its id. */
static void *watch_thread(void *arg) {
    ppc_managed_proxy *p = arg;
    ppc_manager *m = p->m;
    int status = 0;
    for (;;) {
        pid_t r = waitpid(p->pid, &status, WNOHANG);
        if (r == p->pid) break;
        if (r < 0 && errno != EINTR) { status = -1; break; }
        if (atomic_load(&m->freeing)) return NULL;
        sleep_ms(POLL_STEP_MS);
    }
    int code = -1;
    if (status >= 0) {
        if (WIFEXITED(status)) code = WEXITSTATUS(status);
        else if (WIFSIGNALED(status)) code = -WTERMSIG(status);
    }
    p->exit_code = code;
    atomic_store(&p->exited, true);
    char id_text[37];
    ppc_uuid_str(&p->id, id_text);
    if (atomic_load(&p->current)) {
        LOG_WARNING("PPM: %s process %d (proxy %s) exited with code %d. It will be relaunched on the next request for it.",
                    ppc_manifest_name(m->manifest), (int)p->pid, id_text, code);
        char reason[64];
        snprintf(reason, sizeof reason, "process exited with code %d", code);
        lose(m, p, reason);
    } else {
        LOG_DEBUG("PPM: %s process %d (proxy %s) exited with code %d after its peer was already replaced or removed.",
                  ppc_manifest_name(m->manifest), (int)p->pid, id_text, code);
    }
    return NULL;
}

/* The environment of a launched proxy: this process's, the manifest's (placeholders resolved, {python} being this
 * manager's interpreter), the manager's, and the launch marker. */
static char **build_environment(ppc_manager *m) {
    size_t n = 0;
    for (char **e = environ; e && *e; e++) n++;
    const char *const *mf_names;
    size_t n_mf = ppc_manifest_environment(m->manifest, &mf_names, NULL);
    char **resolved = ppc_manifest_resolved_environment(m->manifest, ppc_manager_python(m), &n_mf);
    const char *const *mf_values = (const char *const *)resolved;
    char **env = resolved || n_mf == 0 ? calloc(n + n_mf + m->n_env + 2, sizeof *env) : NULL;
    if (env == NULL) { ppc_strings_free(resolved, n_mf); return NULL; }
    size_t count = 0;
    for (char **e = environ; e && *e; e++) if ((env[count] = ppc_strdup(*e)) != NULL) count++;
    struct { const char *const *names, *const *values; size_t n; } layers[3] = {
        {mf_names, mf_values, n_mf}, {(const char *const *)m->env_names, (const char *const *)m->env_values, m->n_env},
        {(const char *const[]){PPC_LAUNCHED_BY_MANAGER_ENV}, (const char *const[]){"1"}, 1}};
    for (int l = 0; l < 3; l++) {
        for (size_t i = 0; i < layers[l].n; i++) {
            const char *name = layers[l].names[i], *value = layers[l].values[i];
            size_t name_len = strlen(name);
            char *entry = malloc(name_len + strlen(value) + 2);
            if (entry == NULL) continue;
            snprintf(entry, name_len + strlen(value) + 2, "%s=%s", name, value);
            bool replaced = false;
            for (size_t k = 0; k < count; k++)
                if (strncmp(env[k], name, name_len) == 0 && env[k][name_len] == '=') { free(env[k]); env[k] = entry; replaced = true; break; }
            if (!replaced) env[count++] = entry;
        }
    }
    env[count] = NULL;
    ppc_strings_free(resolved, n_mf);
    return env;
}

static void close_pair(int fds[2]) {
    if (fds[0] >= 0) close(fds[0]);
    if (fds[1] >= 0) close(fds[1]);
    fds[0] = fds[1] = -1;
}

/* Start the proxy's process, write the stdin handshake (section 1) and start the pipe readers and the watcher. */
static int launch(ppc_manager *m, ppc_managed_proxy *p, char *err, size_t err_len) {
    if (p->argc == 0) { set_err(err, err_len, "%s: empty launch command", ppc_manifest_name(m->manifest)); return PPC_ERR_INVALID; }
    int in[2] = {-1, -1}, out[2] = {-1, -1}, errp[2] = {-1, -1};
    if (pipe2(in, O_CLOEXEC) != 0 || pipe2(out, O_CLOEXEC) != 0 || pipe2(errp, O_CLOEXEC) != 0) {
        set_err(err, err_len, "pipe: %s", strerror(errno));
        close_pair(in); close_pair(out); close_pair(errp);
        return PPC_ERR_IO;
    }
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, in[0], 0);
    posix_spawn_file_actions_adddup2(&actions, out[1], 1);
    posix_spawn_file_actions_adddup2(&actions, errp[1], 2);
    char **env = build_environment(m);
    pid_t pid = 0;
    int rc = env ? posix_spawnp(&pid, p->command[0], &actions, NULL, p->command, env) : ENOMEM;
    posix_spawn_file_actions_destroy(&actions);
    if (env) { for (char **e = env; *e; e++) free(*e); free(env); }
    close(in[0]); close(out[1]); close(errp[1]);
    if (rc != 0) {
        set_err(err, err_len, "%s: unable to launch %s: %s", ppc_manifest_name(m->manifest), p->command[0], strerror(rc));
        close(in[1]); close(out[0]); close(errp[0]);
        return PPC_ERR_IO;
    }
    p->pid = pid;
    p->out_fd = out[0];
    p->err_fd = errp[0];
    atomic_store(&p->launched, true);
    LOG_INFO("proxy %s has PID %d", p->name, (int)pid);
    reader_arg *ro = calloc(1, sizeof *ro), *re = calloc(1, sizeof *re);
    if (ro) { *ro = (reader_arg){p, out[0], "stdout"}; if (pthread_create(&p->out_thread, NULL, reader_thread, ro) == 0) p->has_out = true; else { free(ro); close(out[0]); } }
    if (re) { *re = (reader_arg){p, errp[0], "stderr"}; if (pthread_create(&p->err_thread, NULL, reader_thread, re) == 0) p->has_err = true; else { free(re); close(errp[0]); } }
    char id_text[37];
    ppc_uuid_str(&p->id, id_text);
    LOG_INFO("PPM: Created new ProtocolProxy %s with ID %s, pid: %d", p->name, id_text, (int)pid);

    ppc_buf handshake = {0};
    char hex[65];
    ppc_hex_encode(p->token.b, 16, hex);
    ppc_buf_append(&handshake, hex, 32);
    ppc_hex_encode(m->token.b, 16, hex);
    ppc_buf_append(&handshake, hex, 32);
    if (p->has_key) { ppc_hex_encode(p->aead_key, PPC_KEY_BYTES, hex); ppc_buf_append(&handshake, hex, 64); }
    if (p->material) {
        char *line = ppc_tls_material_line(p->material);
        if (line) { ppc_buf_append(&handshake, line, strlen(line)); free(line); }
    }
    size_t written = 0;
    while (handshake.data && written < handshake.len) {
        ssize_t n = write(in[1], handshake.data + written, handshake.len - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { LOG_WARNING("PPM: unable to write the handshake to %s (pid %d): %s", p->name, (int)pid, strerror(errno)); break; }
        written += (size_t)n;
    }
    if (handshake.data) memset(handshake.data, 0, handshake.len);
    ppc_buf_free(&handshake);
    close(in[1]);
    if (pthread_create(&p->watch_thread, NULL, watch_thread, p) == 0) p->has_watch = true;
    else LOG_ERROR("PPM: unable to start the watcher for %s (pid %d)", p->name, (int)pid);
    return PPC_OK;
}

/* ---- launch options ------------------------------------------------------------------------------------------- */
typedef struct {
    char **names, **values;
    size_t n;
} option_set;

static const char *set_get(const option_set *s, const char *name) {
    for (size_t i = 0; i < s->n; i++) if (strcmp(s->names[i], name) == 0) return s->values[i];
    return NULL;
}

static int set_put(option_set *s, const char *name, const char *value) {
    for (size_t i = 0; i < s->n; i++)
        if (strcmp(s->names[i], name) == 0) { char *v = ppc_strdup(value); if (v == NULL) return PPC_ERR_NOMEM; free(s->values[i]); s->values[i] = v; return PPC_OK; }
    char **names = realloc(s->names, (s->n + 1) * sizeof *names);
    if (names == NULL) return PPC_ERR_NOMEM;
    s->names = names;
    char **values = realloc(s->values, (s->n + 1) * sizeof *values);
    if (values == NULL) return PPC_ERR_NOMEM;
    s->values = values;
    s->names[s->n] = ppc_strdup(name);
    s->values[s->n] = ppc_strdup(value);
    if (s->names[s->n] == NULL || s->values[s->n] == NULL) return PPC_ERR_NOMEM;
    s->n++;
    return PPC_OK;
}

static void set_remove(option_set *s, const char *name) {
    for (size_t i = 0; i < s->n; i++)
        if (strcmp(s->names[i], name) == 0) {
            free(s->names[i]); free(s->values[i]);
            memmove(s->names + i, s->names + i + 1, (s->n - i - 1) * sizeof *s->names);
            memmove(s->values + i, s->values + i + 1, (s->n - i - 1) * sizeof *s->values);
            s->n--;
            return;
        }
}

static void set_free(option_set *s) {
    ppc_strings_free(s->names, s->n);
    ppc_strings_free(s->values, s->n);
    memset(s, 0, sizeof *s);
}

static void set_sort(option_set *s) {
    for (size_t i = 1; i < s->n; i++)
        for (size_t j = i; j > 0 && strcmp(s->names[j - 1], s->names[j]) > 0; j--) {
            char *t = s->names[j]; s->names[j] = s->names[j - 1]; s->names[j - 1] = t;
            t = s->values[j]; s->values[j] = s->values[j - 1]; s->values[j - 1] = t;
        }
}

static bool manager_only(const char *name) {
    for (size_t i = 0; i < sizeof MANAGER_ONLY_OPTIONS / sizeof *MANAGER_ONLY_OPTIONS; i++)
        if (strcmp(name, MANAGER_ONLY_OPTIONS[i]) == 0) return true;
    return false;
}

typedef struct { char **items; size_t n; } argv_list;

static int argv_push(argv_list *l, const char *s) {
    char **items = realloc(l->items, (l->n + 2) * sizeof *items);
    if (items == NULL) return PPC_ERR_NOMEM;
    l->items = items;
    l->items[l->n] = ppc_strdup(s);
    if (l->items[l->n] == NULL) return PPC_ERR_NOMEM;
    l->n++;
    l->items[l->n] = NULL;
    return PPC_OK;
}

/* The SSH launcher prefix of section 1 (composed as the Python manager composes it; not exercised by the tests):
 * ssh -o BatchMode=yes [-R <port>:127.0.0.1:<port>] [ssh_options...] host env <marker> [remote_env...]. Sets *python
 * to the remote interpreter. Nothing when ssh_host is absent. */
static int launcher_prefix(ppc_manager *m, const ppc_option *options, size_t n_options, argv_list *prefix,
                           const char **python) {
    const char *host = ppc_options_get(options, n_options, "ssh_host");
    *python = ppc_manager_python(m);
    if (host == NULL || *host == '\0') return PPC_OK;
    int rc = argv_push(prefix, "ssh");
    rc = rc ? rc : argv_push(prefix, "-o");
    rc = rc ? rc : argv_push(prefix, "BatchMode=yes");
    if (ppc_option_bool(ppc_options_get(options, n_options, "ssh_forward"), true)) {
        int port = 0;
        ppc_connector_local_address(m->c, NULL, 0, &port);
        char forward[64];
        snprintf(forward, sizeof forward, "%d:127.0.0.1:%d", port, port);
        rc = rc ? rc : argv_push(prefix, "-R");
        rc = rc ? rc : argv_push(prefix, forward);
    }
    const char *ssh_options = ppc_options_get(options, n_options, "ssh_options");    /* whitespace-separated */
    if (ssh_options) {
        char *copy = ppc_strdup(ssh_options);
        for (char *tok = copy ? strtok(copy, " \t") : NULL; tok && rc == PPC_OK; tok = strtok(NULL, " \t")) rc = argv_push(prefix, tok);
        free(copy);
    }
    rc = rc ? rc : argv_push(prefix, host);
    rc = rc ? rc : argv_push(prefix, "env");
    rc = rc ? rc : argv_push(prefix, PPC_LAUNCHED_BY_MANAGER_ENV "=1");
    const char *remote_env = ppc_options_get(options, n_options, "remote_env");     /* whitespace-separated K=V */
    if (remote_env) {
        char *copy = ppc_strdup(remote_env);
        for (char *tok = copy ? strtok(copy, " \t") : NULL; tok && rc == PPC_OK; tok = strtok(NULL, " \t")) rc = argv_push(prefix, tok);
        free(copy);
    }
    const char *remote_python = ppc_options_get(options, n_options, "remote_python");
    *python = remote_python && *remote_python ? remote_python : "python3";
    return rc;
}

/* Where the manager must dial a proxy launched with manager_dials: the "dial" option ("host:port"), else the proxy's
 * inbound_address/inbound_port launch options. *address stays NULL for a proxy that dials in. */
static int dial_target(const ppc_option *options, size_t n_options, char **address, int *port, char *err, size_t err_len) {
    *address = NULL;
    *port = 0;
    if (!ppc_option_bool(ppc_options_get(options, n_options, "manager_dials"), false)) return PPC_OK;
    const char *dial = ppc_options_get(options, n_options, "dial");
    if (dial && *dial) {
        const char *colon = strrchr(dial, ':');
        if (colon == NULL || atoi(colon + 1) <= 0) { set_err(err, err_len, "dial must be host:port, got \"%s\"", dial); return PPC_ERR_INVALID; }
        *address = malloc((size_t)(colon - dial) + 1);
        if (*address == NULL) return PPC_ERR_NOMEM;
        memcpy(*address, dial, (size_t)(colon - dial));
        (*address)[colon - dial] = '\0';
        *port = atoi(colon + 1);
        return PPC_OK;
    }
    const char *inbound_port = ppc_options_get(options, n_options, "inbound_port");
    if (inbound_port == NULL || atoi(inbound_port) <= 0) {
        set_err(err, err_len, "manager_dials=true needs the proxy's inbound_port (and inbound_address) or a dial=host:port");
        return PPC_ERR_INVALID;
    }
    const char *inbound_address = ppc_options_get(options, n_options, "inbound_address");
    *address = ppc_strdup(inbound_address && *inbound_address ? inbound_address : "localhost");
    *port = atoi(inbound_port);
    return *address ? PPC_OK : PPC_ERR_NOMEM;
}

/* Build the proxy's peer, launch command and secrets from its options (the manager lock is held). */
static ppc_managed_proxy *prepare(ppc_manager *m, const ppc_uuid *id, const char *name, const ppc_json *key,
                                  const ppc_option *options, size_t n_options, char *err, size_t err_len) {
    ppc_managed_proxy *p = calloc(1, sizeof *p);
    if (p == NULL) return NULL;
    p->m = m;
    p->id = *id;
    p->state = "launching";
    atomic_init(&p->current, false);
    atomic_init(&p->launched, false);
    atomic_init(&p->exited, false);
    atomic_init(&p->terminating, false);
    atomic_init(&p->registered, false);
    atomic_init(&p->log_level, m->proxy_log_level);
    p->out_fd = p->err_fd = -1;
    p->name = ppc_strdup(name);
    p->key = ppc_json_clone(key);
    p->logger_name = ppc_proxy_logger_name(ppc_manifest_name(m->manifest), name);
    if (p->name == NULL || p->key == NULL || p->logger_name == NULL || ppc_uuid_random(&p->token) != PPC_OK) { proxy_free(p); return NULL; }

    option_set launch = {0};
    argv_list prefix = {0};
    argv_list standard = {0};
    char **argv = NULL;
    int rc = PPC_OK;
    for (size_t i = 0; i < n_options && rc == PPC_OK; i++)
        if (options[i].name && options[i].value && !manager_only(options[i].name)) rc = set_put(&launch, options[i].name, options[i].value);
    const char *python = NULL;
    if (rc == PPC_OK) rc = launcher_prefix(m, options, n_options, &prefix, &python);
    if (rc == PPC_OK && prefix.n && ppc_option_bool(ppc_options_get(options, n_options, "ssh_forward"), true) && set_get(&launch, "manager_address") == NULL)
        rc = set_put(&launch, "manager_address", "127.0.0.1");          /* the forwarded port on the proxy's host */
    if (rc == PPC_OK && set_get(&launch, "log_level") == NULL) rc = set_put(&launch, "log_level", ppc_log_level_name(m->proxy_log_level));
    if (rc == PPC_OK && m->encrypt && set_get(&launch, "encrypt") == NULL) rc = set_put(&launch, "encrypt", "true");
    bool encrypt = ppc_option_bool(set_get(&launch, "encrypt"), false);
    if (rc == PPC_OK && encrypt && set_get(&launch, "cipher") == NULL) rc = set_put(&launch, "cipher", ppc_connector_cipher(m->c));
    if (rc == PPC_OK && m->ipc_tls && set_get(&launch, "ipc_tls") == NULL) rc = set_put(&launch, "ipc_tls", "true");
    bool use_tls = ppc_option_bool(set_get(&launch, "ipc_tls"), false);
    char *manager_address = ppc_strdup(set_get(&launch, "manager_address") ? set_get(&launch, "manager_address") : m->inbound_address);
    set_remove(&launch, "manager_address");
    int persistent = -1;
    if (set_get(&launch, "persistent")) persistent = ppc_option_bool(set_get(&launch, "persistent"), false) ? 1 : 0;
    if (rc == PPC_OK) rc = dial_target(options, n_options, &p->dial_address, &p->dial_port, err, err_len);
    if (p->dial_address) persistent = 1;
    if (rc == PPC_OK) {
        set_sort(&launch);
        char hex[33], port_text[16];
        int port = 0;
        ppc_connector_local_address(m->c, NULL, 0, &port);
        snprintf(port_text, sizeof port_text, "%d", port);
        ppc_uuid_hex(&p->id, hex);
        rc = argv_push(&standard, "--proxy-id"); rc = rc ? rc : argv_push(&standard, hex);
        rc = rc ? rc : argv_push(&standard, "--proxy-name"); rc = rc ? rc : argv_push(&standard, name);
        ppc_uuid_hex(ppc_connector_id(m->c), hex);
        rc = rc ? rc : argv_push(&standard, "--manager-id"); rc = rc ? rc : argv_push(&standard, hex);
        rc = rc ? rc : argv_push(&standard, "--manager-address"); rc = rc ? rc : argv_push(&standard, manager_address ? manager_address : "localhost");
        rc = rc ? rc : argv_push(&standard, "--manager-port"); rc = rc ? rc : argv_push(&standard, port_text);
        for (size_t i = 0; i < launch.n && rc == PPC_OK; i++) {
            char flag[160];
            snprintf(flag, sizeof flag, "--%s", launch.names[i]);
            for (char *q = flag; *q; q++) if (*q == '_') *q = '-';
            rc = argv_push(&standard, flag);
            rc = rc ? rc : argv_push(&standard, launch.values[i]);
        }
    }
    if (rc == PPC_OK) {
        size_t n_cmd = 0;
        char **cmd = ppc_manifest_launch_command(m->manifest, python, (const char *const *)standard.items, standard.n, &n_cmd);
        if (cmd == NULL) rc = PPC_ERR_NOMEM;
        else {
            argv = calloc(prefix.n + n_cmd + 1, sizeof *argv);
            if (argv == NULL) rc = PPC_ERR_NOMEM;
            else {
                size_t n = 0;
                for (size_t i = 0; i < prefix.n; i++) argv[n++] = prefix.items[i];
                for (size_t i = 0; i < n_cmd; i++) argv[n++] = cmd[i];
                p->command = argv;
                p->argc = n;
                free(prefix.items);         /* strings now owned by argv */
                prefix.items = NULL; prefix.n = 0;
                free(cmd);
            }
        }
    }
    free(manager_address);
    set_free(&launch);
    ppc_strings_free(prefix.items, prefix.n);
    ppc_strings_free(standard.items, standard.n);
    if (rc != PPC_OK) {
        if (err && err_len && err[0] == '\0') set_err(err, err_len, "unable to prepare the launch: %s", ppc_strerror(rc));
        proxy_free(p);
        return NULL;
    }
    if (encrypt) {
        if (ppc_random_bytes(p->aead_key, PPC_KEY_BYTES) != PPC_OK) { proxy_free(p); return NULL; }
        p->has_key = true;
    }
    if (use_tls) {
        char hex[33];
        ppc_uuid_hex(&p->id, hex);
        p->material = ppc_authority_issue(m->authority, hex, NULL, 0, err, err_len);
        if (p->material == NULL) { proxy_free(p); return NULL; }
        p->tls = true;
    }
    p->peer = ppc_connector_add_peer(m->c, &p->id, &p->token, p->dial_address, p->dial_port, p->has_key ? p->aead_key : NULL,
                                     persistent, p->tls);
    if (p->peer == NULL) { set_err(err, err_len, "unable to add the peer"); proxy_free(p); return NULL; }
    return p;
}

/* ---- registration, LOG --------------------------------------------------------------------------------------- */
static int handle_register_peer(ppc_connector *c, const ppc_header *h, const uint8_t *payload, size_t len,
                                uint8_t **reply, size_t *reply_len, void *user) {
    (void)c;
    ppc_manager *m = user;
    char sender[33];
    ppc_uuid_hex(&h->sender_id, sender);
    ppc_managed_proxy *p = ppc_manager_proxy_by_id(m, &h->sender_id);
    const char *refused = "false";
    if (p == NULL) {
        LOG_ERROR("PPM: Received registration message from unknown peer: %s.", sender);
        *reply = (uint8_t *)ppc_strdup(refused); *reply_len = 5;
        return PPC_OK;
    }
    char err[64];
    ppc_json *reg = ppc_json_parse((const char *)payload, len, err, sizeof err);
    const char *address = ppc_json_get_string(reg, "address", NULL);
    int port = (int)ppc_json_get_number(reg, "port", 0);
    if (reg == NULL || reg->type != PPC_JSON_OBJECT || address == NULL || *address == '\0' || port == 0) {
        LOG_ERROR("PPM: Failed to register peer: %s with message: %.*s.", sender, (int)len, (const char *)payload);
        ppc_json_free(reg);
        *reply = (uint8_t *)ppc_strdup(refused); *reply_len = 5;
        return PPC_OK;
    }
    ppc_connector_set_peer_address(m->c, p->peer, address, port);
    const ppc_json *features = ppc_json_get(reg, "features");
    const char **names = NULL;
    size_t n = 0;
    if (features && features->type == PPC_JSON_ARRAY && features->count) {
        names = calloc(features->count, sizeof *names);
        for (size_t i = 0; names && i < features->count; i++)
            if (features->items[i]->type == PPC_JSON_STRING) names[n++] = features->items[i]->string;
    }
    ppc_peer_set_features(p->peer, names, n);
    const char *cipher = ppc_json_get_string(reg, "cipher", NULL);
    pthread_mutex_lock(&m->lock);
    p->state = "registered";
    p->last_seen = ppc_now();
    free(p->cipher);
    p->cipher = cipher ? ppc_strdup(cipher) : NULL;
    atomic_store(&p->registered, true);
    pthread_cond_broadcast(&m->cond);
    pthread_mutex_unlock(&m->lock);
    ppc_buf list = {0};
    for (size_t i = 0; i < n; i++) { if (i) ppc_buf_append(&list, ", ", 2); ppc_buf_append(&list, names[i], strlen(names[i])); }
    ppc_buf_append(&list, "", 1);
    LOG_INFO("PPM: Successfully registered peer: %s @ %s:%d (features: %s%s%s)", sender, address, port,
             list.data ? (char *)list.data : "", cipher && p->has_key ? "; encrypts with " : "", cipher && p->has_key ? cipher : "");
    ppc_buf_free(&list);
    free(names);
    ppc_json_free(reg);
    ppc_json *o = ppc_json_new_object();
    ppc_json *fs = ppc_json_new_array();
    for (size_t i = 0; i < sizeof MANAGER_FEATURES / sizeof *MANAGER_FEATURES; i++) ppc_json_array_append(fs, ppc_json_new_string(MANAGER_FEATURES[i]));
    ppc_json_object_set(o, "registered", ppc_json_new_bool(true));
    ppc_json_object_set(o, "features", fs);
    char *text = ppc_json_dump(o);
    ppc_json_free(o);
    if (text == NULL) return PPC_ERR_NOMEM;
    *reply = (uint8_t *)text;
    *reply_len = strlen(text);
    return PPC_OK;
}

static int handle_log(ppc_connector *c, const ppc_header *h, const uint8_t *payload, size_t len, uint8_t **reply,
                      size_t *reply_len, void *user) {
    (void)c; (void)reply; (void)reply_len;
    ppc_manager *m = user;
    ppc_managed_proxy *p = ppc_manager_proxy_by_id(m, &h->sender_id);
    char sender[33];
    ppc_uuid_hex(&h->sender_id, sender);
    if (p == NULL) { LOG_WARNING("PPM: LOG batch from unknown peer %s ignored.", sender); return PPC_OK; }
    ppc_record *records = NULL;
    size_t n = 0;
    if (ppc_records_from_batch((const char *)payload, len, p->logger_name, (int)p->pid, p->name, &records, &n) != PPC_OK) {
        LOG_WARNING("PPM: Undecodable LOG batch from %s.", p->name);
        return PPC_OK;
    }
    for (size_t i = 0; i < n; i++) emit_record(p, &records[i]);
    free(records);
    return PPC_OK;
}

/* ---- heartbeat, dialling -------------------------------------------------------------------------------------- */
static void ping(ppc_manager *m, ppc_managed_proxy *p) {
    ppc_message msg = {"PING", NULL, 0, true, NULL, 2, false};
    uint8_t *reply = NULL;
    size_t reply_len = 0;
    int rc = ppc_connector_request(m->c, p->peer, &msg, m->heartbeat_timeout, &reply, &reply_len);
    if (rc == PPC_OK) {
        char err[64];
        ppc_json *report = reply ? ppc_json_parse((const char *)reply, reply_len, err, sizeof err) : NULL;
        pthread_mutex_lock(&m->lock);
        p->last_seen = ppc_now();
        p->missed = 0;
        p->state = "healthy";
        if (report && report->type == PPC_JSON_OBJECT && strcmp(ppc_json_get_string(report, "status", ""), "error") != 0) {
            ppc_json_free(p->health);
            p->health = report;
            report = NULL;
        }
        pthread_mutex_unlock(&m->lock);
        ppc_json_free(report);
        free(reply);
        return;
    }
    free(reply);
    if (!atomic_load(&p->current)) return;
    char why[80];
    if (rc == PPC_ERR_TIMEOUT) snprintf(why, sizeof why, "no reply within %g s", m->heartbeat_timeout);
    else snprintf(why, sizeof why, "%s", ppc_strerror(rc));
    pthread_mutex_lock(&m->lock);
    int missed = ++p->missed;
    bool lost = missed >= m->heartbeat_misses;
    p->state = lost ? "lost" : "unhealthy";
    pthread_mutex_unlock(&m->lock);
    if (lost) {
        LOG_WARNING("PPM: %s missed heartbeat %d of %d (%s).", p->name, missed, m->heartbeat_misses, why);
        char reason[64];
        snprintf(reason, sizeof reason, "missed %d heartbeats", missed);
        lose(m, p, reason);
    } else {
        LOG_INFO("PPM: %s missed heartbeat %d of %d (%s).", p->name, missed, m->heartbeat_misses, why);
    }
}

static void *heartbeat_thread(void *arg) {
    ppc_manager *m = arg;
    while (!atomic_load(&m->stopped)) {
        double deadline = ppc_monotonic() + m->heartbeat_interval;
        while (!atomic_load(&m->stopped) && ppc_monotonic() < deadline) sleep_ms(50);
        if (atomic_load(&m->stopped)) break;
        size_t n = 0;
        ppc_managed_proxy **list = ppc_manager_proxies(m, &n);
        for (size_t i = 0; list && i < n && !atomic_load(&m->stopped); i++) {
            ppc_managed_proxy *p = list[i];
            /* only registered proxies with a live process that this manager is not stopping (a stopping proxy
             * refuses connections, which is not a miss) */
            if (atomic_load(&p->registered) && ppc_managed_proxy_running(p) && !atomic_load(&p->terminating)) ping(m, p);
        }
        free(list);
    }
    return NULL;
}

static void start_heartbeat(ppc_manager *m) {
    if (!m->heartbeat_enabled) return;
    pthread_mutex_lock(&m->lock);
    if (!m->heartbeating && pthread_create(&m->heartbeat_thread, NULL, heartbeat_thread, m) == 0) m->heartbeating = true;
    pthread_mutex_unlock(&m->lock);
}

/* For a proxy that cannot dial in: open the persistent connection to it and PING until it has registered over that
 * connection (it adopts the connection once the frame authenticates as this manager). */
static void *dial_thread(void *arg) {
    ppc_managed_proxy *p = arg;
    ppc_manager *m = p->m;
    while (atomic_load(&p->current) && !atomic_load(&p->registered) && !atomic_load(&m->stopped)) {
        ppc_message msg = {"PING", NULL, 0, true, NULL, 2, false};
        uint8_t *reply = NULL;
        size_t reply_len = 0;
        int rc = ppc_connector_request(m->c, p->peer, &msg, m->heartbeat_timeout, &reply, &reply_len);
        free(reply);
        if (rc != PPC_OK) LOG_DEBUG("PPM: %s not reachable yet at %s:%d: %s", p->name, p->dial_address, p->dial_port, ppc_strerror(rc));
        double deadline = ppc_monotonic() + DIAL_RETRY_INTERVAL;
        while (atomic_load(&p->current) && !atomic_load(&p->registered) && !atomic_load(&m->stopped) && ppc_monotonic() < deadline) sleep_ms(POLL_STEP_MS);
    }
    return NULL;
}

/* ---- get_proxy ------------------------------------------------------------------------------------------------ */
int ppc_manager_start(ppc_manager *m) {
    if (m == NULL) return PPC_ERR_INVALID;
    int rc = ppc_connector_start(m->c);
    if (rc != PPC_OK) return rc;
    pthread_mutex_lock(&m->lock);
    m->started = true;
    pthread_mutex_unlock(&m->lock);
    return PPC_OK;
}

static key_entry *key_entry_locked(ppc_manager *m, const char *key_text, const ppc_option *options, size_t n_options,
                                   char *err, size_t err_len) {
    for (key_entry *e = m->keys; e; e = e->next) {
        if (strcmp(e->key, key_text) != 0) continue;
        char *conflicts = ppc_manifest_conflicts(m->manifest, e->shared, e->n_shared, options, n_options);
        if (conflicts) {
            set_err(err, err_len, "remote would share proxy process %s but differs in %s, which the %s manifest requires to match",
                    key_text, conflicts, ppc_manifest_name(m->manifest));
            free(conflicts);
            return NULL;
        }
        return e;
    }
    key_entry *e = calloc(1, sizeof *e);
    if (e == NULL) return NULL;
    e->key = ppc_strdup(key_text);
    const char *const *must_match;
    size_t n_mm = ppc_manifest_must_match(m->manifest, &must_match);
    e->shared = calloc(n_mm + 1, sizeof *e->shared);
    for (size_t i = 0; e->shared && i < n_mm; i++) {
        const char *value = ppc_options_get(options, n_options, must_match[i]);
        e->shared[e->n_shared].name = ppc_strdup(must_match[i]);
        e->shared[e->n_shared].value = value ? ppc_strdup(value) : NULL;
        e->n_shared++;
    }
    if (e->key == NULL || ppc_uuid_random(&e->id) != PPC_OK) {
        free(e->key);
        for (size_t i = 0; i < e->n_shared; i++) { free((char *)e->shared[i].name); free((char *)e->shared[i].value); }
        free(e->shared);
        free(e);
        return NULL;
    }
    e->next = m->keys;
    m->keys = e;
    return e;
}

ppc_managed_proxy *ppc_manager_get_proxy(ppc_manager *m, const char *const *unique_remote_id, size_t id_count,
                                         const ppc_option *options, size_t n_options, char *err, size_t err_len) {
    if (err && err_len) err[0] = '\0';
    if (m == NULL) return NULL;
    pthread_mutex_lock(&m->lock);
    if (!m->started) { pthread_mutex_unlock(&m->lock); set_err(err, err_len, "the manager has not been started"); return NULL; }
    if (atomic_load(&m->stopped)) { pthread_mutex_unlock(&m->lock); set_err(err, err_len, "the manager is stopped"); return NULL; }
    ppc_json *key = ppc_manifest_process_key(m->manifest, unique_remote_id, id_count, options, n_options);
    char *key_text = key ? ppc_py_tuple(key) : NULL;
    if (key_text == NULL) { pthread_mutex_unlock(&m->lock); ppc_json_free(key); return NULL; }
    key_entry *e = key_entry_locked(m, key_text, options, n_options, err, err_len);
    if (e == NULL) { pthread_mutex_unlock(&m->lock); ppc_json_free(key); free(key_text); return NULL; }
    ppc_managed_proxy *p = find_current_locked(m, &e->id);
    if (p) { pthread_mutex_unlock(&m->lock); ppc_json_free(key); free(key_text); return p; }
    p = prepare(m, &e->id, key_text, key, options, n_options, err, err_len);
    ppc_json_free(key);
    free(key_text);
    if (p == NULL) { pthread_mutex_unlock(&m->lock); return NULL; }
    atomic_store(&p->current, true);
    p->next = m->all;
    m->all = p;
    pthread_mutex_unlock(&m->lock);

    int rc = launch(m, p, err, err_len);
    if (rc != PPC_OK) {
        pthread_mutex_lock(&m->lock);
        atomic_store(&p->current, false);
        p->state = "lost";
        p->lost_reason = ppc_strdup("launch failed");
        ppc_connector_remove_peer(m->c, &p->id);
        pthread_mutex_unlock(&m->lock);
        return NULL;
    }
    if (p->dial_address) {
        if (pthread_create(&p->dial_thread, NULL, dial_thread, p) == 0) p->has_dial = true;
        else LOG_WARNING("PPM: unable to start dialling %s", p->name);
    }
    start_heartbeat(m);
    char id_text[37];
    ppc_uuid_str(&p->id, id_text);
    LOG_INFO("PPM: Proxy %s created, waiting for registration before sending.", id_text);
    return p;
}

int ppc_manager_wait_registered(ppc_manager *m, ppc_managed_proxy *p, double timeout) {
    if (m == NULL || p == NULL) return PPC_ERR_INVALID;
    struct timespec deadline;
    deadline_after(&deadline, timeout);
    pthread_mutex_lock(&m->lock);
    int rc = PPC_OK;
    while (!atomic_load(&p->registered) && atomic_load(&p->current)) {
        if (pthread_cond_timedwait(&m->cond, &m->lock, &deadline) == ETIMEDOUT) { rc = PPC_ERR_TIMEOUT; break; }
    }
    if (rc == PPC_OK && !atomic_load(&p->registered)) rc = PPC_ERR_CONNECTION;
    pthread_mutex_unlock(&m->lock);
    if (rc == PPC_ERR_TIMEOUT) {
        char id_text[37], reason[80];
        ppc_uuid_str(&p->id, id_text);
        LOG_WARNING("Peer %s did not register within %g seconds. Removing peer.", id_text, timeout);
        snprintf(reason, sizeof reason, "did not register within %g seconds", timeout);
        lose(m, p, reason);
    }
    return rc;
}

/* ---- requests ------------------------------------------------------------------------------------------------- */
int ppc_manager_request(ppc_manager *m, ppc_managed_proxy *p, const ppc_message *msg, double timeout,
                        uint8_t **reply, size_t *reply_len) {
    if (m == NULL || p == NULL || msg == NULL) return PPC_ERR_INVALID;
    return ppc_connector_request(m->c, p->peer, msg, timeout, reply, reply_len);
}

int ppc_manager_send(ppc_manager *m, ppc_managed_proxy *p, const ppc_message *msg) {
    if (m == NULL || p == NULL || msg == NULL) return PPC_ERR_INVALID;
    return ppc_connector_send(m->c, p->peer, msg);
}

int ppc_manager_set_proxy_log_level(ppc_manager *m, ppc_managed_proxy *p, int level, double timeout,
                                    uint8_t **reply, size_t *reply_len) {
    if (m == NULL || p == NULL) return PPC_ERR_INVALID;
    atomic_store(&p->log_level, level);
    char body[64];
    snprintf(body, sizeof body, "{\"level\": \"%s\"}", ppc_log_level_name(level));
    ppc_message msg = {"SET_LOG_LEVEL", (const uint8_t *)body, strlen(body), true, NULL, 2, false};
    return ppc_connector_request(m->c, p->peer, &msg, timeout, reply, reply_len);
}

/* ---- health --------------------------------------------------------------------------------------------------- */
char *ppc_manager_health_json(ppc_manager *m) {
    ppc_json *out = ppc_json_new_object();
    if (out == NULL) return NULL;
    size_t n = 0;
    ppc_managed_proxy **list = ppc_manager_proxies(m, &n);
    for (size_t i = 0; list && i < n; i++) {
        ppc_managed_proxy *p = list[i];
        ppc_json *h = ppc_json_new_object();
        char id_text[37];
        ppc_uuid_str(&p->id, id_text);
        pthread_mutex_lock(&m->lock);
        ppc_json_object_set(h, "proxy_id", ppc_json_new_string(id_text));
        ppc_json_object_set(h, "state", ppc_json_new_string(p->state));
        ppc_json_object_set(h, "last_seen", p->last_seen > 0 ? ppc_json_new_number(p->last_seen) : ppc_json_new_null());
        ppc_json_object_set(h, "missed", ppc_json_new_integer(p->missed));
        ppc_json_object_set(h, "report", p->health ? ppc_json_clone(p->health) : ppc_json_new_null());
        pthread_mutex_unlock(&m->lock);
        size_t nf = 0;
        char **features = ppc_peer_features(p->peer, &nf);
        ppc_json *fs = ppc_json_new_array();
        for (size_t k = 0; k < nf; k++) ppc_json_array_append(fs, ppc_json_new_string(features[k]));
        ppc_strings_free(features, nf);
        ppc_json_object_set(h, "features", fs);
        ppc_json_object_set(h, "persistent", ppc_json_new_bool(ppc_peer_persistent(p->peer, m->c)));
        ppc_json_object_set(h, "connected", ppc_json_new_bool(ppc_peer_linked(p->peer)));
        ppc_json_object_set(h, "pid", ppc_json_new_integer((long long)ppc_managed_proxy_pid(p)));
        ppc_json_object_set(out, p->name, h);
    }
    free(list);
    char *text = ppc_json_dump(out);
    ppc_json_free(out);
    return text;
}

/* ---- self test ------------------------------------------------------------------------------------------------ */
int ppc_manager_self_test(ppc_manager *m, char *err, size_t err_len) {
    if (err && err_len) err[0] = '\0';
    size_t argc = 0;
    char **argv = ppc_manifest_self_test_command(m->manifest, ppc_manager_python(m), &argc);
    if (argv == NULL) return PPC_OK;
    int out[2];
    if (pipe2(out, O_CLOEXEC) != 0) { ppc_strings_free(argv, argc); return PPC_ERR_IO; }
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, out[1], 1);
    posix_spawn_file_actions_adddup2(&actions, out[1], 2);
    char **env = build_environment(m);
    pid_t pid = 0;
    int rc = env ? posix_spawnp(&pid, argv[0], &actions, NULL, argv, env) : ENOMEM;
    posix_spawn_file_actions_destroy(&actions);
    if (env) { for (char **e = env; *e; e++) free(*e); free(env); }
    close(out[1]);
    if (rc != 0) {
        set_err(err, err_len, "%s self test %s failed to start: %s", ppc_manifest_name(m->manifest), argv[0], strerror(rc));
        close(out[0]);
        ppc_strings_free(argv, argc);
        return PPC_ERR_IO;
    }
    ppc_buf output = {0};
    char chunk[4096];
    ssize_t n;
    while ((n = read(out[0], chunk, sizeof chunk)) > 0 || (n < 0 && errno == EINTR)) if (n > 0) ppc_buf_append(&output, chunk, (size_t)n);
    close(out[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    ppc_buf_append(&output, "", 1);
    int result = PPC_OK;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        set_err(err, err_len, "%s self test %s failed (status %d)\n%s", ppc_manifest_name(m->manifest), argv[0],
                WIFEXITED(status) ? WEXITSTATUS(status) : -1, output.data ? (char *)output.data : "");
        result = PPC_ERR_IO;
    }
    ppc_buf_free(&output);
    ppc_strings_free(argv, argc);
    return result;
}

/* ---- stopping ------------------------------------------------------------------------------------------------- */
void ppc_manager_stop(ppc_manager *m, bool terminate_proxies, double timeout) {
    if (m == NULL) return;
    if (atomic_exchange(&m->stopped, true)) return;
    if (timeout <= 0) timeout = PPC_MANAGER_TERMINATE_TIMEOUT;
    pthread_mutex_lock(&m->lock);
    bool heartbeating = m->heartbeating;
    m->heartbeating = false;
    pthread_mutex_unlock(&m->lock);
    if (heartbeating) pthread_join(m->heartbeat_thread, NULL);
    ppc_connector_stop(m->c);
    if (!terminate_proxies) return;
    pthread_mutex_lock(&m->lock);
    size_t n = 0;
    for (ppc_managed_proxy *p = m->all; p; p = p->next) if (ppc_managed_proxy_running(p)) n++;
    ppc_managed_proxy **running = calloc(n + 1, sizeof *running);
    size_t i = 0;
    for (ppc_managed_proxy *p = m->all; running && p; p = p->next) if (ppc_managed_proxy_running(p)) running[i++] = p;
    pthread_mutex_unlock(&m->lock);
    if (running == NULL) return;
    for (size_t k = 0; k < n; k++) {
        atomic_store(&running[k]->terminating, true);
        LOG_INFO("Terminating %s with PID: %d", ppc_manifest_name(m->manifest), (int)running[k]->pid);
        kill(running[k]->pid, SIGTERM);
    }
    for (int pass = 0; pass < 2; pass++) {
        double deadline = ppc_monotonic() + timeout;
        bool all_exited = false;
        while (!all_exited && ppc_monotonic() < deadline) {
            all_exited = true;
            for (size_t k = 0; k < n; k++) if (!atomic_load(&running[k]->exited)) all_exited = false;
            if (!all_exited) sleep_ms(POLL_STEP_MS);
        }
        if (all_exited) break;
        for (size_t k = 0; k < n; k++)
            if (!atomic_load(&running[k]->exited)) {
                if (pass == 0) { LOG_INFO("Killing %s with PID: %d", ppc_manifest_name(m->manifest), (int)running[k]->pid); kill(running[k]->pid, SIGKILL); }
                else LOG_WARNING("Failed to stop %s with PID: %d", ppc_manifest_name(m->manifest), (int)running[k]->pid);
            }
    }
    for (size_t k = 0; k < n; k++) atomic_store(&running[k]->terminating, false);
    free(running);
}

void ppc_manager_free(ppc_manager *m) {
    if (m == NULL) return;
    if (m->c) ppc_manager_stop(m, true, PPC_MANAGER_TERMINATE_TIMEOUT);
    /* Let the watchers reap what has exited, then release every thread. */
    for (ppc_managed_proxy *p = m->all; p; p = p->next) if (p->has_watch && atomic_load(&p->exited)) { pthread_join(p->watch_thread, NULL); p->has_watch = false; }
    atomic_store(&m->freeing, true);
    for (ppc_managed_proxy *p = m->all; p; p = p->next) {
        if (p->has_watch) pthread_join(p->watch_thread, NULL);
        if (p->has_out) pthread_join(p->out_thread, NULL);
        if (p->has_err) pthread_join(p->err_thread, NULL);
        if (p->has_dial) pthread_join(p->dial_thread, NULL);
        if (p->has_term) pthread_join(p->term_thread, NULL);
    }
    while (m->all) { ppc_managed_proxy *p = m->all; m->all = p->next; proxy_free(p); }
    while (m->keys) {
        key_entry *e = m->keys;
        m->keys = e->next;
        free(e->key);
        for (size_t i = 0; i < e->n_shared; i++) { free((char *)e->shared[i].name); free((char *)e->shared[i].value); }
        free(e->shared);
        free(e);
    }
    while (m->lost) { lost_cb *cb = m->lost; m->lost = cb->next; free(cb); }
    ppc_connector_free(m->c);
    ppc_tls_material_free(m->material);
    ppc_authority_free(m->authority);
    ppc_strings_free(m->env_names, m->n_env);
    ppc_strings_free(m->env_values, m->n_env);
    pthread_mutex_destroy(&m->lock);
    pthread_cond_destroy(&m->cond);
    free(m->name);
    free(m->inbound_address);
    free(m->python);
    free(m);
}
