/* The IPC connector (sections 2, 3, 4, 5, 6): listener, dialer, per-message and persistent connections in both
 * directions, frame authentication and sealing, dispatch, and RESPONSE matching by request id.
 *
 * Threads: one accept thread, one reader thread per accepted or dialled persistent connection. Handlers run on the
 * reader thread of the connection the request arrived on. All sockets are non-blocking; every wait is a poll() that
 * also watches the connector's stop pipe, so stop() wakes everything promptly. */
#include "internal.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_MIN_PORT 22801
#define DEFAULT_MAX_PORT 22899
#define DEFAULT_IO_TIMEOUT 30.0
#define DEFAULT_MAX_FRAME (256u * 1024u * 1024u)
#define LISTEN_BACKLOG 128
#define KEEPIDLE 15
#define KEEPINTVL 5
#define KEEPCNT 4

typedef struct ppc_conn ppc_conn;

struct ppc_peer {
    ppc_uuid id, token;
    char *address;
    int port;
    bool has_key;
    uint8_t key[PPC_KEY_BYTES];
    int persistent;                 /* -1: connector default */
    bool tls;
    char **features;
    size_t n_features;
    ppc_conn *connection;           /* live persistent connection (one reference held) */
    double last_seen;
    struct ppc_peer *next;
};

struct ppc_conn {
    ppc_connector *c;
    int fd;
    void *ssl;
    bool accepted;
    bool persistent;
    bool has_peer;
    ppc_uuid peer_id;
    bool has_tls_peer;
    char tls_peer[256];
    pthread_mutex_t write_lock;
    atomic_int urgent;              /* frames waiting for or holding write_lock that are not low priority */
    pthread_t thread;
    bool has_thread;
    atomic_bool closed;             /* shutdown requested */
    atomic_bool done;               /* reader thread finished */
    atomic_int refs;
    uint32_t *pending;              /* request ids awaiting responses on this connection */
    size_t n_pending, cap_pending;
    char name[64];
    struct ppc_conn *next;
};

typedef struct handler {
    char method[PPC_METHOD_MAX + 1];
    bool has_remote;
    ppc_uuid remote;
    ppc_handler_fn fn;
    void *user;
    bool provides_response;
    struct handler *next;
} handler;

typedef struct pending {
    uint32_t id;
    bool done;
    int error;
    uint8_t *payload;
    size_t len;
    struct pending *next;
} pending;

struct ppc_connector {
    ppc_uuid id, token;
    char *name;
    char *inbound_address;
    int inbound_port, min_port, max_port;
    bool persistent;
    size_t persistent_max_frame;
    long compress_threshold;        /* -1: never */
    char *cipher;
    double io_timeout;
    size_t max_frame;
    bool tls_accept_plain;
    struct ppc_tls_ctx *tls_server, *tls_client;

    int listen_fd;
    char local_address[64];
    int local_port;
    int stop_pipe[2];
    atomic_bool stop;
    bool started;
    pthread_t accept_thread;
    bool accepting;

    pthread_mutex_t lock;
    pthread_cond_t cond;
    ppc_peer *peers;
    ppc_peer *retired;              /* removed peers, kept until free (handlers may still hold them) */
    ppc_conn *conns;
    handler *handlers;
    pending *pendings;
    uint32_t next_id_v1, next_id_v2;
    double last_activity;
};

/* ---- small helpers -------------------------------------------------------------------------------------------- */
static int wait_fd(void *arg, int fd, short events, int timeout_ms) {
    ppc_connector *c = arg;
    struct pollfd pfd[2] = {{fd, events, 0}, {c->stop_pipe[0], POLLIN, 0}};
    for (;;) {
        if (atomic_load(&c->stop)) return PPC_ERR_STOPPED;
        int n = poll(pfd, 2, timeout_ms);
        if (n < 0) { if (errno == EINTR) continue; return PPC_ERR_IO; }
        if (n == 0) return 0;
        if (pfd[1].revents) return PPC_ERR_STOPPED;
        return 1;
    }
}

static void set_keepalive(int fd) {
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
    int v = KEEPIDLE; setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &v, sizeof v);
    v = KEEPINTVL; setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &v, sizeof v);
    v = KEEPCNT; setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &v, sizeof v);
}

static int remaining_ms(double deadline) {
    if (deadline <= 0) return -1;
    double left = (deadline - ppc_monotonic()) * 1000.0;
    return left <= 0 ? 0 : (int)left + 1;
}

static void describe_fd(int fd, char *out, size_t out_len) {
    struct sockaddr_in sa;
    socklen_t sl = sizeof sa;
    if (getpeername(fd, (struct sockaddr *)&sa, &sl) == 0 && sa.sin_family == AF_INET) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sa.sin_addr, ip, sizeof ip);
        snprintf(out, out_len, "%s:%d", ip, ntohs(sa.sin_port));
    } else {
        snprintf(out, out_len, "fd %d", fd);
    }
}

const char *ppc_connector_name(const ppc_connector *c) { return c->name; }
const ppc_uuid *ppc_connector_id(const ppc_connector *c) { return &c->id; }
const char *ppc_connector_cipher(const ppc_connector *c) { return c->cipher; }
bool ppc_connector_stopping(const ppc_connector *c) { return atomic_load(&c->stop); }
double ppc_connector_last_activity(const ppc_connector *c) { return c->last_activity; }
const ppc_uuid *ppc_peer_id(const ppc_peer *p) { return &p->id; }

char *ppc_error_payload(const char *method_name, const char *error) {
    ppc_json *o = ppc_json_new_object();
    if (o == NULL) return NULL;
    ppc_json_object_set(o, "status", ppc_json_new_string("error"));
    ppc_json_object_set(o, "error", ppc_json_new_string(error));
    ppc_json_object_set(o, "method", ppc_json_new_string(method_name));
    char *text = ppc_json_dump(o);
    ppc_json_free(o);
    return text;
}

/* ---- connections ---------------------------------------------------------------------------------------------- */
static ppc_conn *conn_new(ppc_connector *c, int fd, bool accepted) {
    ppc_conn *conn = calloc(1, sizeof *conn);
    if (conn == NULL) return NULL;
    conn->c = c;
    conn->fd = fd;
    conn->accepted = accepted;
    pthread_mutex_init(&conn->write_lock, NULL);
    atomic_init(&conn->urgent, 0);
    atomic_init(&conn->refs, 1);
    atomic_init(&conn->closed, false);
    atomic_init(&conn->done, false);
    describe_fd(fd, conn->name, sizeof conn->name);
    return conn;
}

static void conn_ref(ppc_conn *conn) { atomic_fetch_add(&conn->refs, 1); }

static void conn_shutdown(ppc_conn *conn) {
    if (!atomic_exchange(&conn->closed, true)) shutdown(conn->fd, SHUT_RDWR);
}

static void conn_unref(ppc_conn *conn) {
    if (atomic_fetch_sub(&conn->refs, 1) != 1) return;
    if (conn->ssl) ppc_tls_free(conn->ssl);
    if (conn->fd >= 0) close(conn->fd);
    pthread_mutex_destroy(&conn->write_lock);
    free(conn->pending);
    free(conn);
}

static bool conn_alive(const ppc_conn *conn) {
    return conn != NULL && !atomic_load(&conn->closed) && !atomic_load(&conn->done);
}

static void conn_make_persistent(ppc_conn *conn, const ppc_uuid *peer_id) {
    conn->persistent = true;
    if (peer_id) { conn->peer_id = *peer_id; conn->has_peer = true; }
    set_keepalive(conn->fd);
}

/* Under c->lock. */
static void conn_track_pending(ppc_conn *conn, uint32_t id) {
    if (conn->n_pending == conn->cap_pending) {
        size_t cap = conn->cap_pending ? conn->cap_pending * 2 : 8;
        uint32_t *p = realloc(conn->pending, cap * sizeof *p);
        if (p == NULL) return;
        conn->pending = p;
        conn->cap_pending = cap;
    }
    conn->pending[conn->n_pending++] = id;
}

static void conn_untrack_pending(ppc_conn *conn, uint32_t id) {
    for (size_t i = 0; i < conn->n_pending; i++)
        if (conn->pending[i] == id) { conn->pending[i] = conn->pending[--conn->n_pending]; return; }
}

/* Raw reads and writes on a connection's socket or TLS session. */
static ssize_t conn_read(ppc_conn *conn, uint8_t *buf, size_t len, int timeout_ms) {
    if (conn->ssl) return ppc_tls_read(conn->ssl, buf, len, wait_fd, conn->c, timeout_ms);
    double deadline = timeout_ms < 0 ? 0 : ppc_monotonic() + timeout_ms / 1000.0;
    for (;;) {
        ssize_t n = recv(conn->fd, buf, len, 0);
        if (n > 0) return n;
        if (n == 0) return 0;
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) return PPC_ERR_CONNECTION;
        int w = wait_fd(conn->c, conn->fd, POLLIN, timeout_ms < 0 ? -1 : remaining_ms(deadline));
        if (w == 0) return PPC_ERR_TIMEOUT;
        if (w < 0) return w;
    }
}

/* PPC_OK, 1 for a clean EOF before any byte, or a negative code. */
static int conn_read_exact(ppc_conn *conn, uint8_t *buf, size_t len, int timeout_ms) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = conn_read(conn, buf + got, len - got, timeout_ms);
        if (n == 0) return got == 0 ? 1 : PPC_ERR_CONNECTION;
        if (n < 0) return (int)n;
        got += (size_t)n;
    }
    return PPC_OK;
}

#define LOW_PRIORITY_WAIT_MS 500

/* Write one frame. A low-priority frame (a LOG batch) waits, up to LOW_PRIORITY_WAIT_MS, while any other frame is
 * waiting for or holding the connection's write lock, so it never delays a request or a reply; every frame is still
 * written whole under write_lock. */
static int conn_write_all(ppc_conn *conn, const uint8_t *buf, size_t len, bool low_priority) {
    int timeout_ms = (int)(conn->c->io_timeout * 1000);
    if (low_priority) {
        double deadline = ppc_monotonic() + LOW_PRIORITY_WAIT_MS / 1000.0;
        while (atomic_load(&conn->urgent) > 0 && !atomic_load(&conn->closed) && ppc_monotonic() < deadline) {
            struct timespec ts = {0, 1000000L};
            nanosleep(&ts, NULL);
        }
    } else {
        atomic_fetch_add(&conn->urgent, 1);
    }
    pthread_mutex_lock(&conn->write_lock);
    int rc = PPC_OK;
    if (atomic_load(&conn->closed)) rc = PPC_ERR_CONNECTION;
    else if (conn->ssl) rc = ppc_tls_write(conn->ssl, buf, len, wait_fd, conn->c, timeout_ms);
    else {
        double deadline = ppc_monotonic() + conn->c->io_timeout;
        while (len) {
            ssize_t n = send(conn->fd, buf, len, MSG_NOSIGNAL);
            if (n >= 0) { buf += n; len -= (size_t)n; continue; }
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK) { rc = PPC_ERR_CONNECTION; break; }
            int w = wait_fd(conn->c, conn->fd, POLLOUT, remaining_ms(deadline));
            if (w == 0) { rc = PPC_ERR_TIMEOUT; break; }
            if (w < 0) { rc = w; break; }
        }
    }
    pthread_mutex_unlock(&conn->write_lock);
    if (!low_priority) atomic_fetch_sub(&conn->urgent, 1);
    return rc;
}

/* ---- peers ---------------------------------------------------------------------------------------------------- */
static ppc_peer *find_peer_locked(ppc_connector *c, const ppc_uuid *id) {
    for (ppc_peer *p = c->peers; p; p = p->next)
        if (ppc_uuid_equal(&p->id, id)) return p;
    return NULL;
}

ppc_peer *ppc_connector_find_peer(ppc_connector *c, const ppc_uuid *id) {
    pthread_mutex_lock(&c->lock);
    ppc_peer *p = find_peer_locked(c, id);
    pthread_mutex_unlock(&c->lock);
    return p;
}

ppc_peer *ppc_connector_add_peer(ppc_connector *c, const ppc_uuid *id, const ppc_uuid *token, const char *address,
                                 int port, const uint8_t *key, int persistent, bool tls) {
    ppc_peer *p = calloc(1, sizeof *p);
    if (p == NULL) return NULL;
    p->id = *id;
    p->token = *token;
    p->address = address ? ppc_strdup(address) : NULL;
    p->port = port;
    if (key) { memcpy(p->key, key, PPC_KEY_BYTES); p->has_key = true; }
    p->persistent = persistent;
    p->tls = tls;
    pthread_mutex_lock(&c->lock);
    ppc_peer *existing = find_peer_locked(c, id);
    if (existing) {
        pthread_mutex_unlock(&c->lock);
        free(p->address);
        free(p);
        return existing;
    }
    p->next = c->peers;
    c->peers = p;
    pthread_mutex_unlock(&c->lock);
    return p;
}

static void peer_free(ppc_peer *p) {
    for (size_t i = 0; i < p->n_features; i++) free(p->features[i]);
    free(p->features);
    free(p->address);
    if (p->connection) conn_unref(p->connection);
    memset(p->key, 0, sizeof p->key);
    free(p);
}

/* Features change rarely (at registration) but may be read by a reader thread while the main thread sets them, so
 * they have a lock of their own: the connector lock is not reachable from a peer. */
static pthread_mutex_t features_lock = PTHREAD_MUTEX_INITIALIZER;

void ppc_peer_set_features(ppc_peer *p, const char *const *features, size_t count) {
    char **copy = count ? calloc(count, sizeof *copy) : NULL;
    size_t n = 0;
    for (size_t i = 0; copy && i < count; i++) if ((copy[n] = ppc_strdup(features[i])) != NULL) n++;
    pthread_mutex_lock(&features_lock);
    char **old = p->features;
    size_t old_n = p->n_features;
    p->features = copy;
    p->n_features = n;
    pthread_mutex_unlock(&features_lock);
    for (size_t i = 0; i < old_n; i++) free(old[i]);
    free(old);
}

bool ppc_peer_has_feature(ppc_peer *p, const char *feature) {
    bool found = false;
    pthread_mutex_lock(&features_lock);
    for (size_t i = 0; i < p->n_features && !found; i++)
        if (strcmp(p->features[i], feature) == 0) found = true;
    pthread_mutex_unlock(&features_lock);
    return found;
}

size_t ppc_peer_feature_count(ppc_peer *p) { return p->n_features; }

char **ppc_peer_features(ppc_peer *p, size_t *count) {
    pthread_mutex_lock(&features_lock);
    char **copy = p->n_features ? calloc(p->n_features, sizeof *copy) : NULL;
    size_t n = 0;
    for (size_t i = 0; copy && i < p->n_features; i++) if ((copy[n] = ppc_strdup(p->features[i])) != NULL) n++;
    pthread_mutex_unlock(&features_lock);
    if (count) *count = n;
    return copy;
}

void ppc_strings_free(char **list, size_t count) {
    if (list == NULL) return;
    for (size_t i = 0; i < count; i++) free(list[i]);
    free(list);
}

bool ppc_peer_has_key(const ppc_peer *p) { return p->has_key; }
bool ppc_peer_tls(const ppc_peer *p) { return p->tls; }
bool ppc_peer_persistent(const ppc_peer *p, const ppc_connector *c) { return p->persistent < 0 ? c->persistent : p->persistent != 0; }

int ppc_connector_set_peer_address(ppc_connector *c, ppc_peer *p, const char *address, int port) {
    if (c == NULL || p == NULL) return PPC_ERR_INVALID;
    char *copy = address ? ppc_strdup(address) : NULL;
    if (address && copy == NULL) return PPC_ERR_NOMEM;
    pthread_mutex_lock(&c->lock);
    free(p->address);
    p->address = copy;
    p->port = address ? port : 0;
    pthread_mutex_unlock(&c->lock);
    return PPC_OK;
}

void ppc_connector_remove_peer(ppc_connector *c, const ppc_uuid *id) {
    if (c == NULL || id == NULL) return;
    pthread_mutex_lock(&c->lock);
    ppc_peer *found = NULL;
    for (ppc_peer **pp = &c->peers; *pp; pp = &(*pp)->next)
        if (ppc_uuid_equal(&(*pp)->id, id)) { found = *pp; *pp = found->next; break; }
    if (found) {
        if (found->connection) {
            conn_shutdown(found->connection);
            conn_unref(found->connection);
            found->connection = NULL;
        }
        found->next = c->retired;
        c->retired = found;
    }
    pthread_mutex_unlock(&c->lock);
}

bool ppc_peer_linked(ppc_peer *p) { return conn_alive(p->connection); }

static bool is_persistent(ppc_connector *c, ppc_peer *p) {
    return p->persistent < 0 ? c->persistent : p->persistent != 0;
}

/* Replace the peer's persistent connection (under c->lock); the previous one is shut down. */
static void peer_set_connection_locked(ppc_connector *c, ppc_peer *p, ppc_conn *conn) {
    ppc_conn *previous = p->connection;
    if (conn) conn_ref(conn);
    p->connection = conn;
    if (previous && previous != conn) {
        if (conn_alive(previous)) {
            char hex[33];
            ppc_uuid_hex(&p->id, hex);
            LOG_INFO("%s: %s opened a new persistent connection; closing %s.", c->name, hex, previous->name);
            conn_shutdown(previous);
        }
        conn_unref(previous);
    }
}

/* ---- handlers ------------------------------------------------------------------------------------------------- */
int ppc_connector_register_handler(ppc_connector *c, const char *method_name, const ppc_uuid *remote_id,
                                   ppc_handler_fn fn, void *user, bool provides_response) {
    if (c == NULL || method_name == NULL || strlen(method_name) > PPC_METHOD_MAX) return PPC_ERR_INVALID;
    pthread_mutex_lock(&c->lock);
    for (handler *h = c->handlers; h; h = h->next) {
        if (strcmp(h->method, method_name) != 0) continue;
        if (remote_id == NULL && !h->has_remote) {
            pthread_mutex_unlock(&c->lock);
            LOG_INFO("%s confirmed callback: %s is registered.", c->name, method_name);
            return PPC_OK;      /* first registration wins */
        }
        if (remote_id && h->has_remote && ppc_uuid_equal(&h->remote, remote_id)) {
            h->fn = fn; h->user = user; h->provides_response = provides_response;      /* last one wins */
            pthread_mutex_unlock(&c->lock);
            return PPC_OK;
        }
    }
    handler *h = calloc(1, sizeof *h);
    if (h == NULL) { pthread_mutex_unlock(&c->lock); return PPC_ERR_NOMEM; }
    snprintf(h->method, sizeof h->method, "%s", method_name);
    if (remote_id) { h->remote = *remote_id; h->has_remote = true; }
    h->fn = fn;
    h->user = user;
    h->provides_response = provides_response;
    h->next = c->handlers;
    c->handlers = h;
    pthread_mutex_unlock(&c->lock);
    LOG_INFO("%s registered callback: %s", c->name, method_name);
    return PPC_OK;
}

/* Under c->lock: the remote's own handler if the message names one it has, else the method's. */
static handler *find_handler_locked(ppc_connector *c, const ppc_header *h) {
    handler *by_method = NULL;
    bool has_remote = h->version >= 2 && !ppc_uuid_is_nil(&h->remote_id);
    for (handler *e = c->handlers; e; e = e->next) {
        if (strcmp(e->method, h->method_name) != 0) continue;
        if (e->has_remote) { if (has_remote && ppc_uuid_equal(&e->remote, &h->remote_id)) return e; }
        else if (by_method == NULL) by_method = e;
    }
    return by_method;
}

size_t ppc_connector_remote_count(const ppc_connector *c) {
    size_t n = 0;
    for (handler *e = c->handlers; e; e = e->next) {
        if (!e->has_remote) continue;
        bool seen = false;
        for (handler *f = c->handlers; f != e; f = f->next)
            if (f->has_remote && ppc_uuid_equal(&f->remote, &e->remote)) { seen = true; break; }
        if (!seen) n++;
    }
    return n;
}

/* ---- pending requests ----------------------------------------------------------------------------------------- */
static uint32_t next_request_id_locked(ppc_connector *c, int version) {
    if (version == 1) {
        uint32_t id = c->next_id_v1;
        c->next_id_v1 = id >= PPC_REQUEST_ID_MAX_V1 - 1 ? 1 : id + 1;      /* cycle(range(1, MAX)) */
        return id;
    }
    uint32_t id = c->next_id_v2;
    c->next_id_v2 = id >= PPC_REQUEST_ID_MAX_V2 - 1 ? 1 : id + 1;
    return id;
}

static pending *pending_add_locked(ppc_connector *c, uint32_t id) {
    pending *p = calloc(1, sizeof *p);
    if (p == NULL) return NULL;
    p->id = id;
    p->next = c->pendings;
    c->pendings = p;
    return p;
}

static pending *pending_find_locked(ppc_connector *c, uint32_t id) {
    for (pending *p = c->pendings; p; p = p->next) if (p->id == id) return p;
    return NULL;
}

static void pending_remove_locked(ppc_connector *c, pending *target) {
    for (pending **pp = &c->pendings; *pp; pp = &(*pp)->next)
        if (*pp == target) { *pp = target->next; free(target->payload); free(target); return; }
}

static void pending_fail_locked(ppc_connector *c, uint32_t id, int error) {
    pending *p = pending_find_locked(c, id);
    if (p && !p->done) { p->done = true; p->error = error; pthread_cond_broadcast(&c->cond); }
}

/* Under c->lock: fail the requests awaiting responses on a lost connection. */
static void conn_fail_pending_locked(ppc_connector *c, ppc_conn *conn) {
    for (size_t i = 0; i < conn->n_pending; i++) pending_fail_locked(c, conn->pending[i], PPC_ERR_CONNECTION);
    conn->n_pending = 0;
}

static int pending_wait(ppc_connector *c, pending *p, double timeout, uint8_t **reply, size_t *reply_len) {
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += (time_t)timeout;
    deadline.tv_nsec += (long)((timeout - (double)(time_t)timeout) * 1e9);
    if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&c->lock);
    int rc = PPC_OK;
    while (!p->done) {
        if (atomic_load(&c->stop)) { rc = PPC_ERR_STOPPED; break; }
        int w = pthread_cond_timedwait(&c->cond, &c->lock, &deadline);
        if (w == ETIMEDOUT) { rc = PPC_ERR_TIMEOUT; break; }
    }
    if (rc == PPC_OK) {
        rc = p->error;
        if (rc == PPC_OK) {
            if (reply) { *reply = p->payload; p->payload = NULL; }
            if (reply_len) *reply_len = p->len;
        }
    }
    pending_remove_locked(c, p);
    pthread_mutex_unlock(&c->lock);
    return rc;
}

/* ---- sealing (sections 4 and 5) ------------------------------------------------------------------------------- */
static const char *cipher_for(ppc_connector *c, ppc_peer *peer) {
    if (peer && peer->n_features && !ppc_peer_has_feature(peer, ppc_cipher_feature(c->cipher)))
        return PPC_BASELINE_CIPHER;
    return c->cipher;
}

/* The frame bytes of a message toward peer: header then payload, compressed when the peer takes it and encrypted
 * when a key is shared with it. */
static int build_frame(ppc_connector *c, ppc_peer *peer, const char *method, uint32_t request_id, int version,
                       bool response_expected, bool keep_alive, const ppc_uuid *remote_id, const uint8_t *payload,
                       size_t payload_len, uint8_t **out, size_t *out_len) {
    uint8_t *compressed = NULL;
    bool is_compressed = false;
    if (peer && c->compress_threshold != -1 && ppc_peer_has_feature(peer, "compress")) {
        long threshold = c->compress_threshold == PPC_COMPRESS_EVERYTHING ? 0 : c->compress_threshold;
        if ((long)payload_len > threshold) {
            size_t clen;
            int rc = ppc_zlib_compress(payload, payload_len, &compressed, &clen);
            if (rc != PPC_OK) return rc;
            payload = compressed;
            payload_len = clen;
            is_compressed = true;
        }
    }
    ppc_header h;
    memset(&h, 0, sizeof h);
    h.version = (uint16_t)(version == 1 ? 1 : 2);
    snprintf(h.method_name, sizeof h.method_name, "%s", method);
    h.request_id = request_id;
    h.sender_id = c->id;
    h.sender_token = c->token;
    if (remote_id && h.version == 2) h.remote_id = *remote_id;
    h.bitflags = (uint16_t)((response_expected ? PPC_FLAG(PPC_BIT_RESPONSE_EXPECTED) : 0)
                            | (is_compressed ? PPC_FLAG(PPC_BIT_COMPRESSED) : 0)
                            | (keep_alive ? PPC_FLAG(PPC_BIT_KEEP_ALIVE) : 0));
    bool encrypt = peer && peer->has_key;
    bool aes_gcm = encrypt && ppc_cipher_is_aes_gcm(cipher_for(c, peer));
    size_t wire_len = encrypt ? payload_len + PPC_NONCE_BYTES + PPC_TAG_BYTES : payload_len;
    h.data_length = wire_len;
    if (encrypt) h.bitflags |= PPC_FLAG(PPC_BIT_ENCRYPTED) | (aes_gcm ? PPC_FLAG(PPC_BIT_AES_GCM) : 0);
    uint8_t header[PPC_FRAME_HEADER_MAX];
    size_t header_len;
    int rc = ppc_header_pack(&h, header, &header_len);
    if (rc != PPC_OK) { free(compressed); return rc; }
    uint8_t *frame = malloc(header_len + wire_len);
    if (frame == NULL) { free(compressed); return PPC_ERR_NOMEM; }
    memcpy(frame, header, header_len);
    if (encrypt) {
        uint8_t *nonce = frame + header_len;
        if ((rc = ppc_random_bytes(nonce, PPC_NONCE_BYTES)) != PPC_OK
            || (rc = ppc_aead_seal(aes_gcm, peer->key, nonce, header, header_len, payload, payload_len,
                                   nonce + PPC_NONCE_BYTES)) != PPC_OK) {
            free(frame); free(compressed); return rc;
        }
    } else if (payload_len) {
        memcpy(frame + header_len, payload, payload_len);
    }
    free(compressed);
    *out = frame;
    *out_len = header_len + wire_len;
    return PPC_OK;
}

/* The payload as the sender had it: decrypted (authenticated against the raw header) when the frame is encrypted,
 * then decompressed. Refuses the wrong mode for the peer. */
static int open_frame(ppc_connector *c, ppc_peer *peer, const ppc_header *h, const uint8_t *raw_header,
                      size_t raw_len, uint8_t *payload, size_t len, uint8_t **out, size_t *out_len) {
    uint8_t *plain = payload;
    size_t plain_len = len;
    uint8_t *decrypted = NULL;
    const char *who = c->name;
    if (ppc_header_flag(h, PPC_BIT_ENCRYPTED)) {
        if (peer == NULL || !peer->has_key) {
            LOG_WARNING("%s: encrypted %s from a peer with whom no key is shared; dropped.", who, h->method_name);
            return PPC_ERR_AUTH;
        }
        if (len < PPC_NONCE_BYTES + PPC_TAG_BYTES) {
            LOG_WARNING("%s: encrypted %s is too short; dropped.", who, h->method_name);
            return PPC_ERR_AUTH;
        }
        decrypted = malloc(len - PPC_NONCE_BYTES - PPC_TAG_BYTES + 1);
        if (decrypted == NULL) return PPC_ERR_NOMEM;
        int rc = ppc_aead_open(ppc_header_flag(h, PPC_BIT_AES_GCM), peer->key, payload, raw_header, raw_len,
                               payload + PPC_NONCE_BYTES, len - PPC_NONCE_BYTES, decrypted);
        if (rc != PPC_OK) {
            free(decrypted);
            LOG_WARNING("%s: %s failed authentication (%s); dropped.", who, h->method_name, ppc_strerror(rc));
            return PPC_ERR_AUTH;
        }
        plain = decrypted;
        plain_len = len - PPC_NONCE_BYTES - PPC_TAG_BYTES;
    } else if (peer && peer->has_key) {
        LOG_WARNING("%s: clear-text %s from a peer who must encrypt; dropped.", who, h->method_name);
        return PPC_ERR_AUTH;
    }
    if (ppc_header_flag(h, PPC_BIT_COMPRESSED)) {
        uint8_t *inflated;
        size_t inflated_len;
        int rc = ppc_zlib_decompress(plain, plain_len, &inflated, &inflated_len, c->max_frame);
        free(decrypted);
        if (rc != PPC_OK) {
            LOG_WARNING("%s: %s has a corrupt compressed payload; dropped.", who, h->method_name);
            return PPC_ERR_INVALID;
        }
        *out = inflated;
        *out_len = inflated_len;
        return PPC_OK;
    }
    if (decrypted) { *out = decrypted; *out_len = plain_len; return PPC_OK; }
    uint8_t *copy = malloc(plain_len + 1);
    if (copy == NULL) return PPC_ERR_NOMEM;
    if (plain_len) memcpy(copy, plain, plain_len);
    copy[plain_len] = 0;
    *out = copy;
    *out_len = plain_len;
    return PPC_OK;
}

/* ---- receiving ------------------------------------------------------------------------------------------------ */
/* One frame from the connection. PPC_OK with *payload malloc'd (NUL-terminated for convenience), 1 for a clean EOF,
 * or a negative code. */
static int read_frame(ppc_conn *conn, ppc_header *h, uint8_t *raw_header, size_t *raw_len, uint8_t **payload,
                      int timeout_ms) {
    ppc_connector *c = conn->c;
    int rc = conn_read_exact(conn, raw_header, 2, timeout_ms);
    if (rc != PPC_OK) return rc;
    uint16_t version = (uint16_t)((raw_header[0] << 8) | raw_header[1]);
    size_t total = ppc_header_length(version);
    if (total == 0) {
        LOG_WARNING("%s: unknown protocol version %u from %s.", c->name, version, conn->name);
        return PPC_ERR_PROTOCOL;
    }
    rc = conn_read_exact(conn, raw_header + 2, total - 2, timeout_ms);
    if (rc == 1) rc = PPC_ERR_CONNECTION;
    if (rc != PPC_OK) {
        if (rc == PPC_ERR_CONNECTION) LOG_WARNING("%s: %s closed the connection inside a header.", c->name, conn->name);
        return rc;
    }
    if ((rc = ppc_header_unpack(raw_header, total, h)) != PPC_OK) return rc;
    *raw_len = total;
    if (h->data_length > c->max_frame) {
        LOG_WARNING("%s: %s from %s announces %llu payload bytes, above the limit; dropped.", c->name, h->method_name,
                    conn->name, (unsigned long long)h->data_length);
        return PPC_ERR_PROTOCOL;
    }
    uint8_t *data = malloc((size_t)h->data_length + 1);
    if (data == NULL) return PPC_ERR_NOMEM;
    rc = conn_read_exact(conn, data, (size_t)h->data_length, timeout_ms);
    if (rc == 1) rc = PPC_ERR_CONNECTION;
    if (rc != PPC_OK) {
        free(data);
        if (rc == PPC_ERR_CONNECTION)
            LOG_WARNING("%s: %s closed the connection inside the payload of %s (request_id: %u).", c->name, conn->name,
                        h->method_name, h->request_id);
        return rc;
    }
    data[h->data_length] = 0;
    *payload = data;
    return PPC_OK;
}

static void send_response(ppc_conn *conn, const ppc_header *request, ppc_peer *peer, const uint8_t *payload,
                          size_t len) {
    ppc_connector *c = conn->c;
    uint8_t *frame;
    size_t frame_len;
    int rc = build_frame(c, peer, "RESPONSE", request->request_id, request->version, false, conn->persistent, NULL,
                         payload, len, &frame, &frame_len);
    if (rc == PPC_OK) {
        rc = conn_write_all(conn, frame, frame_len, false);
        free(frame);
    }
    if (rc != PPC_OK && !atomic_load(&c->stop))
        LOG_WARNING("%s: unable to answer %s (request_id: %u) on %s: %s", c->name, request->method_name,
                    request->request_id, conn->name, ppc_strerror(rc));
}

/* Authenticate, open, adopt, and dispatch one frame. Returns PPC_ERR_AUTH when the connection must be dropped. */
static int process_frame(ppc_conn *conn, const ppc_header *h, const uint8_t *raw_header, size_t raw_len,
                         uint8_t *wire_payload) {
    ppc_connector *c = conn->c;
    char sender_hex[33];
    ppc_uuid_hex(&h->sender_id, sender_hex);
    /* Transport identity: over TLS the sender must be who the certificate names; a TLS peer must not arrive plain. */
    pthread_mutex_lock(&c->lock);
    ppc_peer *peer = find_peer_locked(c, &h->sender_id);
    pthread_mutex_unlock(&c->lock);
    if (conn->has_tls_peer) {
        if (strcmp(conn->tls_peer, sender_hex) != 0) {
            LOG_WARNING("%s: frame from %s over a TLS connection authenticated as %s; dropped.", c->name, sender_hex,
                        conn->tls_peer);
            free(wire_payload);
            return PPC_OK;
        }
    } else if (peer && peer->tls) {
        LOG_WARNING("%s: clear-text frame from %s, who must use TLS; dropped.", c->name, sender_hex);
        free(wire_payload);
        return PPC_OK;
    }
    bool response_expected = ppc_header_flag(h, PPC_BIT_RESPONSE_EXPECTED);
    /* Section 6: the sender must be a known peer and present its token. */
    if (peer == NULL || !ppc_uuid_equal(&peer->token, &h->sender_token)) {
        LOG_WARNING("%s: %s from %s %s; dropped.", c->name, h->method_name, sender_hex,
                    peer ? "with a wrong token" : "(unknown peer)");
        free(wire_payload);
        if (response_expected) send_response(conn, h, NULL, NULL, 0);     /* an empty reply, so the caller fails fast */
        return PPC_OK;
    }
    uint8_t *payload = NULL;
    size_t len = 0;
    int rc = open_frame(c, peer, h, raw_header, raw_len, wire_payload, (size_t)h->data_length, &payload, &len);
    free(wire_payload);
    if (rc != PPC_OK) return PPC_ERR_AUTH;
    double now = ppc_now();
    pthread_mutex_lock(&c->lock);
    c->last_activity = now;
    peer->last_seen = now;
    if (ppc_header_flag(h, PPC_BIT_KEEP_ALIVE) && !conn->persistent) {
        conn_make_persistent(conn, &peer->id);
        peer_set_connection_locked(c, peer, conn);
    }
    if (strcmp(h->method_name, "RESPONSE") == 0) {
        conn_untrack_pending(conn, h->request_id);
        pending *p = pending_find_locked(c, h->request_id);
        if (p == NULL || p->done) {
            pthread_mutex_unlock(&c->lock);
            LOG_WARNING("%s: response %u from %s arrived after its request was abandoned.", c->name, h->request_id, sender_hex);
            free(payload);
            return PPC_OK;
        }
        p->payload = payload;
        p->len = len;
        p->done = true;
        pthread_cond_broadcast(&c->cond);
        pthread_mutex_unlock(&c->lock);
        return PPC_OK;
    }
    handler *found = find_handler_locked(c, h);
    handler entry;
    if (found) entry = *found;
    pthread_mutex_unlock(&c->lock);
    if (found == NULL) {
        LOG_WARNING("%s: no callback found for method %s (request_id: %u) from %s.", c->name, h->method_name,
                    h->request_id, sender_hex);
        if (response_expected) {
            char text[128];
            snprintf(text, sizeof text, "Unknown method %s", h->method_name);
            char *body = ppc_error_payload(h->method_name, text);
            if (body) { send_response(conn, h, peer, (const uint8_t *)body, strlen(body)); free(body); }
        }
        free(payload);
        return PPC_OK;
    }
    if (response_expected && !entry.provides_response) {
        char text[128];
        snprintf(text, sizeof text, "Method %s provides no response", h->method_name);
        char *body = ppc_error_payload(h->method_name, text);
        if (body) { send_response(conn, h, peer, (const uint8_t *)body, strlen(body)); free(body); }
    }
    uint8_t *reply = NULL;
    size_t reply_len = 0;
    rc = entry.fn(c, h, payload, len, &reply, &reply_len, entry.user);
    free(payload);
    if (entry.provides_response) {
        if (rc != PPC_OK) {
            LOG_WARNING("%s: callback %s failed: %s", c->name, h->method_name, ppc_strerror(rc));
            free(reply);
            char text[160];
            snprintf(text, sizeof text, "Handler failed: %s", ppc_strerror(rc));
            reply = (uint8_t *)ppc_error_payload(h->method_name, text);
            reply_len = reply ? strlen((char *)reply) : 0;
        }
        send_response(conn, h, peer, reply, reply_len);
    }
    free(reply);
    return PPC_OK;
}

/* Finish a connection: fail what awaited responses on it and detach it from its peer. */
static void conn_lost(ppc_conn *conn, const char *reason) {
    ppc_connector *c = conn->c;
    conn_shutdown(conn);
    pthread_mutex_lock(&c->lock);
    conn_fail_pending_locked(c, conn);
    if (conn->has_peer) {
        ppc_peer *peer = find_peer_locked(c, &conn->peer_id);
        if (peer && peer->connection == conn) {
            peer->connection = NULL;
            conn_unref(conn);
            if (!atomic_load(&c->stop)) {
                char hex[33];
                ppc_uuid_hex(&conn->peer_id, hex);
                LOG_INFO("%s: persistent connection to %s %s.", c->name, hex, reason);
            }
        }
    }
    pthread_mutex_unlock(&c->lock);
    atomic_store(&conn->done, true);
}

/* Accepted connections with TLS material: the handshake (a proxy accepts TLS only unless tls_accept_plain). */
static int conn_secure_accepted(ppc_conn *conn) {
    ppc_connector *c = conn->c;
    if (c->tls_server == NULL) return PPC_OK;
    int timeout_ms = (int)(c->io_timeout * 1000);
    if (c->tls_accept_plain) {
        int w = wait_fd(c, conn->fd, POLLIN, timeout_ms);
        if (w <= 0) return w == 0 ? PPC_ERR_TIMEOUT : w;
        uint8_t first;
        ssize_t n = recv(conn->fd, &first, 1, MSG_PEEK);
        if (n <= 0) {
            if (n < 0) LOG_WARNING("%s: unable to read the first byte from %s: %s", c->name, conn->name, strerror(errno));
            return PPC_ERR_CONNECTION;
        }
        if (first != 0x16) return PPC_OK;
    }
    int rc = ppc_tls_handshake(c->tls_server, conn->fd, true, NULL, wait_fd, c, timeout_ms, &conn->ssl);
    if (rc != PPC_OK) {
        LOG_WARNING("%s: TLS handshake with %s failed: %s", c->name, conn->name, ppc_strerror(rc));
        return rc;
    }
    if (ppc_tls_peer_common_name(conn->ssl, conn->tls_peer, sizeof conn->tls_peer) == PPC_OK) conn->has_tls_peer = true;
    return PPC_OK;
}

static void *serve_thread(void *arg) {
    ppc_conn *conn = arg;
    ppc_connector *c = conn->c;
    const char *reason = "closed by the peer";
    if (conn->accepted && conn_secure_accepted(conn) != PPC_OK) { conn_lost(conn, "failed TLS"); return NULL; }
    while (!atomic_load(&c->stop) && !atomic_load(&conn->closed)) {
        ppc_header h;
        uint8_t raw[PPC_FRAME_HEADER_MAX];
        size_t raw_len = 0;
        uint8_t *payload = NULL;
        int rc = read_frame(conn, &h, raw, &raw_len, &payload, conn->persistent ? -1 : (int)(c->io_timeout * 1000));
        if (rc == 1) break;
        if (rc != PPC_OK) {
            reason = rc == PPC_ERR_STOPPED ? "closed" : ppc_strerror(rc);
            if (rc != PPC_ERR_STOPPED && rc != PPC_ERR_CONNECTION && !atomic_load(&c->stop) && !atomic_load(&conn->closed))
                LOG_WARNING("%s: error serving %s: %s", c->name, conn->name, ppc_strerror(rc));
            break;
        }
        rc = process_frame(conn, &h, raw, raw_len, payload);
        if (rc != PPC_OK) { reason = "refused"; break; }
        if (!conn->persistent) break;       /* per message: one frame, its reply if any, then close */
    }
    conn_lost(conn, reason);
    return NULL;
}

/* Under c->lock: track a connection and start its reader thread. */
static int conn_start_locked(ppc_connector *c, ppc_conn *conn) {
    conn->next = c->conns;
    c->conns = conn;
    if (pthread_create(&conn->thread, NULL, serve_thread, conn) != 0) {
        c->conns = conn->next;
        return PPC_ERR_IO;
    }
    conn->has_thread = true;
    return PPC_OK;
}

/* Join and free connections whose reader threads have finished. */
static void reap(ppc_connector *c, bool all) {
    pthread_mutex_lock(&c->lock);
    ppc_conn *dead = NULL;
    for (ppc_conn **pp = &c->conns; *pp;) {
        ppc_conn *conn = *pp;
        if (all || atomic_load(&conn->done)) {
            *pp = conn->next;
            conn->next = dead;
            dead = conn;
        } else {
            pp = &conn->next;
        }
    }
    pthread_mutex_unlock(&c->lock);
    while (dead) {
        ppc_conn *conn = dead;
        dead = conn->next;
        if (conn->has_thread) pthread_join(conn->thread, NULL);
        conn_unref(conn);
    }
}

static void *accept_thread(void *arg) {
    ppc_connector *c = arg;
    while (!atomic_load(&c->stop)) {
        int w = wait_fd(c, c->listen_fd, POLLIN, 500);
        reap(c, false);
        if (w < 0) break;
        if (w == 0) continue;
        int fd = accept4(c->listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ECONNABORTED) continue;
            if (atomic_load(&c->stop)) break;
            LOG_WARNING("%s: error accepting a connection: %s", c->name, strerror(errno));
            struct timespec ts = {0, 100000000L};
            nanosleep(&ts, NULL);
            continue;
        }
        ppc_conn *conn = conn_new(c, fd, true);
        if (conn == NULL) { close(fd); continue; }
        pthread_mutex_lock(&c->lock);
        int rc = conn_start_locked(c, conn);
        pthread_mutex_unlock(&c->lock);
        if (rc != PPC_OK) { LOG_WARNING("%s: unable to start a reader for %s", c->name, conn->name); conn_unref(conn); }
    }
    return NULL;
}

/* ---- dialling ------------------------------------------------------------------------------------------------- */
static int resolve(const char *host, int port, struct sockaddr_in *out) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char service[16];
    snprintf(service, sizeof service, "%d", port);
    if (getaddrinfo(host, service, &hints, &res) != 0 || res == NULL) return PPC_ERR_IO;
    memcpy(out, res->ai_addr, sizeof *out);
    freeaddrinfo(res);
    return PPC_OK;
}

/* A connected, non-blocking socket (TLS-wrapped for a TLS peer) toward address:port, or a negative code. */
static int dial(ppc_connector *c, ppc_peer *peer, const char *address, int port, double timeout, ppc_conn **out) {
    struct sockaddr_in sa;
    int rc = resolve(address, port, &sa);
    if (rc != PPC_OK) return rc;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return PPC_ERR_IO;
    double deadline = ppc_monotonic() + timeout;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        if (errno != EINPROGRESS) { close(fd); return PPC_ERR_CONNECTION; }
        int w = wait_fd(c, fd, POLLOUT, remaining_ms(deadline));
        if (w <= 0) { close(fd); return w == 0 ? PPC_ERR_TIMEOUT : w; }
        int err = 0;
        socklen_t el = sizeof err;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) { close(fd); return PPC_ERR_CONNECTION; }
    }
    ppc_conn *conn = conn_new(c, fd, false);
    if (conn == NULL) { close(fd); return PPC_ERR_NOMEM; }
    if (peer && peer->tls) {
        if (c->tls_client == NULL) { conn_unref(conn); return PPC_ERR_TLS; }
        char hex[33];
        ppc_uuid_hex(&peer->id, hex);
        rc = ppc_tls_handshake(c->tls_client, fd, false, hex, wait_fd, c, remaining_ms(deadline), &conn->ssl);
        if (rc != PPC_OK) { conn_unref(conn); return rc; }
        snprintf(conn->tls_peer, sizeof conn->tls_peer, "%s", hex);
        conn->has_tls_peer = true;
    }
    *out = conn;
    return PPC_OK;
}

/* Dial a connection for one message: write the frame and, when a reply is expected, read one frame back. */
static int per_message_exchange(ppc_connector *c, ppc_peer *peer, const ppc_message *m, uint32_t request_id,
                                double timeout) {
    int version = m->protocol_version == 1 ? 1 : 2;
    ppc_conn *conn = NULL;
    int rc = dial(c, peer, peer->address, peer->port, timeout, &conn);
    if (rc != PPC_OK) {
        if (!atomic_load(&c->stop))
            LOG_WARNING("%s: unable to send %s (request_id: %u) to %s:%d: %s", c->name, m->method_name, request_id,
                        peer->address, peer->port, ppc_strerror(rc));
        return rc;
    }
    uint8_t *frame;
    size_t frame_len;
    rc = build_frame(c, peer, m->method_name, request_id, version, m->response_expected, false, m->remote_id,
                     m->payload, m->payload_len, &frame, &frame_len);
    if (rc == PPC_OK) {
        rc = conn_write_all(conn, frame, frame_len, false);
        free(frame);
    }
    if (rc == PPC_OK && m->response_expected) {
        ppc_header h;
        uint8_t raw[PPC_FRAME_HEADER_MAX];
        size_t raw_len = 0;
        uint8_t *payload = NULL;
        rc = read_frame(conn, &h, raw, &raw_len, &payload, (int)(timeout * 1000));
        if (rc == 1) {
            LOG_WARNING("%s: %s:%d closed the connection without answering %s (request_id: %u).", c->name, peer->address,
                        peer->port, m->method_name, request_id);
            rc = PPC_ERR_CONNECTION;
        } else if (rc == PPC_OK) {
            rc = process_frame(conn, &h, raw, raw_len, payload);
        }
    }
    conn_shutdown(conn);
    conn_unref(conn);
    return rc;
}

/* The peer's open persistent connection, dialled now if it has none and its address is known. Returns a referenced
 * connection in *out. */
static int link_peer(ppc_connector *c, ppc_peer *peer, double timeout, ppc_conn **out) {
    pthread_mutex_lock(&c->lock);
    if (conn_alive(peer->connection)) { conn_ref(peer->connection); *out = peer->connection; pthread_mutex_unlock(&c->lock); return PPC_OK; }
    pthread_mutex_unlock(&c->lock);
    if (peer->address == NULL || peer->port <= 0) return PPC_ERR_NO_ROUTE;
    ppc_conn *conn = NULL;
    int rc = dial(c, peer, peer->address, peer->port, timeout, &conn);
    if (rc != PPC_OK) return rc;
    conn_make_persistent(conn, &peer->id);
    pthread_mutex_lock(&c->lock);
    if (conn_alive(peer->connection)) {      /* someone else dialled first */
        conn_ref(peer->connection);
        *out = peer->connection;
        pthread_mutex_unlock(&c->lock);
        conn_shutdown(conn);
        conn_unref(conn);
        return PPC_OK;
    }
    rc = conn_start_locked(c, conn);
    if (rc != PPC_OK) { pthread_mutex_unlock(&c->lock); conn_unref(conn); return rc; }
    peer_set_connection_locked(c, peer, conn);
    conn_ref(conn);
    *out = conn;
    pthread_mutex_unlock(&c->lock);
    char hex[33];
    ppc_uuid_hex(&peer->id, hex);
    LOG_INFO("%s: opened a persistent connection to %s @ %s:%d.", c->name, hex, peer->address, peer->port);
    return PPC_OK;
}

static int send_message(ppc_connector *c, ppc_peer *peer, const ppc_message *m, double timeout, uint8_t **reply,
                        size_t *reply_len) {
    if (c == NULL || peer == NULL || m == NULL || m->method_name == NULL) return PPC_ERR_INVALID;
    if (reply) *reply = NULL;
    if (reply_len) *reply_len = 0;
    if (atomic_load(&c->stop)) return PPC_ERR_STOPPED;
    if (timeout <= 0) timeout = c->io_timeout;
    bool has_address = peer->address != NULL && peer->port > 0;
    int version = m->protocol_version == 1 ? 1 : 2;
    pthread_mutex_lock(&c->lock);
    bool linked = conn_alive(peer->connection);
    if (!has_address && !linked) {
        pthread_mutex_unlock(&c->lock);
        char hex[33];
        ppc_uuid_hex(&peer->id, hex);
        LOG_ERROR("%s: refusing to send %s to %s: no open connection and no address to dial.", c->name, m->method_name, hex);
        return PPC_ERR_NO_ROUTE;
    }
    uint32_t request_id = next_request_id_locked(c, version);
    pending *p = NULL;
    if (m->response_expected && (p = pending_add_locked(c, request_id)) == NULL) {
        pthread_mutex_unlock(&c->lock);
        return PPC_ERR_NOMEM;
    }
    pthread_mutex_unlock(&c->lock);
    int rc;
    if (!linked && !is_persistent(c, peer)) {
        rc = per_message_exchange(c, peer, m, request_id, timeout);
    } else {
        uint8_t *frame = NULL;
        size_t frame_len = 0;
        rc = build_frame(c, peer, m->method_name, request_id, version, m->response_expected, true, m->remote_id,
                         m->payload, m->payload_len, &frame, &frame_len);
        if (rc == PPC_OK && has_address && c->persistent_max_frame && frame_len > c->persistent_max_frame) {
            free(frame);        /* its own connection, so it does not delay the frames behind it */
            rc = per_message_exchange(c, peer, m, request_id, timeout);
        } else if (rc == PPC_OK) {
            ppc_conn *conn = NULL;
            rc = link_peer(c, peer, timeout, &conn);
            if (rc == PPC_OK) {
                if (m->response_expected) {
                    pthread_mutex_lock(&c->lock);
                    conn_track_pending(conn, request_id);
                    pthread_mutex_unlock(&c->lock);
                }
                rc = conn_write_all(conn, frame, frame_len, m->low_priority);
                if (rc != PPC_OK) {
                    pthread_mutex_lock(&c->lock);
                    conn_untrack_pending(conn, request_id);
                    pthread_mutex_unlock(&c->lock);
                    conn_shutdown(conn);
                }
                conn_unref(conn);
            }
            free(frame);
            if (rc != PPC_OK && !atomic_load(&c->stop)) {
                char hex[33];
                ppc_uuid_hex(&peer->id, hex);
                LOG_WARNING("%s: unable to send %s (request_id: %u) to %s: %s", c->name, m->method_name, request_id, hex,
                            ppc_strerror(rc));
            }
        }
    }
    if (!m->response_expected) return rc;
    if (rc != PPC_OK) {
        pthread_mutex_lock(&c->lock);
        pending_fail_locked(c, request_id, rc);
        pthread_mutex_unlock(&c->lock);
    }
    return pending_wait(c, p, timeout, reply, reply_len);
}

int ppc_connector_request(ppc_connector *c, ppc_peer *peer, const ppc_message *m, double timeout, uint8_t **reply,
                          size_t *reply_len) {
    return send_message(c, peer, m, timeout, reply, reply_len);
}

int ppc_connector_send(ppc_connector *c, ppc_peer *peer, const ppc_message *m) {
    if (m && m->response_expected) return PPC_ERR_INVALID;
    return send_message(c, peer, m, 0, NULL, NULL);
}

/* ---- lifecycle ------------------------------------------------------------------------------------------------ */
ppc_connector *ppc_connector_new(const ppc_connector_config *cfg) {
    if (cfg == NULL) return NULL;
    const char *cipher = ppc_resolve_cipher(cfg->cipher);
    if (cipher == NULL) return NULL;
    ppc_connector *c = calloc(1, sizeof *c);
    if (c == NULL) return NULL;
    signal(SIGPIPE, SIG_IGN);
    c->id = cfg->proxy_id;
    c->token = cfg->token;
    char hex[37];
    ppc_uuid_str(&c->id, hex);
    c->name = ppc_strdup(cfg->proxy_name ? cfg->proxy_name : hex);
    c->inbound_address = ppc_strdup(cfg->inbound_address ? cfg->inbound_address : "localhost");
    c->inbound_port = cfg->inbound_port;
    c->min_port = cfg->min_port > 0 ? cfg->min_port : DEFAULT_MIN_PORT;
    c->max_port = cfg->max_port > 0 ? cfg->max_port : DEFAULT_MAX_PORT;
    c->persistent = cfg->persistent;
    c->persistent_max_frame = cfg->persistent_max_frame ? cfg->persistent_max_frame : PPC_DEFAULT_PERSISTENT_MAX_FRAME;
    c->compress_threshold = cfg->compress_threshold == 0 ? PPC_DEFAULT_COMPRESS_THRESHOLD : cfg->compress_threshold;
    c->cipher = ppc_strdup(cipher);
    c->io_timeout = cfg->io_timeout > 0 ? cfg->io_timeout : DEFAULT_IO_TIMEOUT;
    c->max_frame = cfg->max_frame ? cfg->max_frame : DEFAULT_MAX_FRAME;
    c->tls_accept_plain = cfg->tls_accept_plain;
    c->listen_fd = -1;
    c->stop_pipe[0] = c->stop_pipe[1] = -1;
    c->next_id_v1 = c->next_id_v2 = 1;
    pthread_mutex_init(&c->lock, NULL);
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&c->cond, &attr);
    pthread_condattr_destroy(&attr);
    atomic_init(&c->stop, false);
    if (c->name == NULL || c->inbound_address == NULL || c->cipher == NULL || pipe2(c->stop_pipe, O_CLOEXEC | O_NONBLOCK) != 0) {
        ppc_connector_free(c);
        return NULL;
    }
    if (cfg->tls) {
        char err[256];
        c->tls_server = ppc_tls_ctx_new(cfg->tls, true, err, sizeof err);
        c->tls_client = c->tls_server ? ppc_tls_ctx_new(cfg->tls, false, err, sizeof err) : NULL;
        if (c->tls_server == NULL || c->tls_client == NULL) {
            LOG_ERROR("%s: unusable TLS material: %s", c->name, err);
            ppc_connector_free(c);
            return NULL;
        }
    }
    return c;
}

static int bind_listener(ppc_connector *c) {
    struct sockaddr_in sa;
    int rc = resolve(c->inbound_address, 0, &sa);
    if (rc != PPC_OK) { LOG_ERROR("%s: cannot resolve inbound address %s", c->name, c->inbound_address); return rc; }
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return PPC_ERR_IO;
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    bool bound = false;
    if (c->inbound_port > 0) {
        sa.sin_port = htons((uint16_t)c->inbound_port);
        if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0) bound = true;
        else LOG_WARNING("%s: unable to bind to provided inbound socket %s:%d (%s). Trying next available.", c->name,
                         c->inbound_address, c->inbound_port, strerror(errno));
    }
    for (int port = c->min_port; !bound && port <= c->max_port; port++) {
        sa.sin_port = htons((uint16_t)port);
        if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0) bound = true;
    }
    if (!bound) {
        LOG_ERROR("%s: unable to bind inbound socket to %s on any port in range %d-%d.", c->name, c->inbound_address,
                  c->min_port, c->max_port);
        close(fd);
        return PPC_ERR_IO;
    }
    if (listen(fd, LISTEN_BACKLOG) != 0) { close(fd); return PPC_ERR_IO; }
    socklen_t sl = sizeof sa;
    getsockname(fd, (struct sockaddr *)&sa, &sl);
    inet_ntop(AF_INET, &sa.sin_addr, c->local_address, sizeof c->local_address);
    c->local_port = ntohs(sa.sin_port);
    c->listen_fd = fd;
    LOG_INFO("Created new inbound server socket: %s:%d.", c->local_address, c->local_port);
    return PPC_OK;
}

int ppc_connector_start(ppc_connector *c) {
    if (c == NULL) return PPC_ERR_INVALID;
    if (c->started) return PPC_OK;
    int rc = bind_listener(c);
    if (rc != PPC_OK) return rc;
    if (pthread_create(&c->accept_thread, NULL, accept_thread, c) != 0) {
        close(c->listen_fd);
        c->listen_fd = -1;
        return PPC_ERR_IO;
    }
    c->accepting = true;
    c->started = true;
    return PPC_OK;
}

int ppc_connector_local_address(ppc_connector *c, char *address, size_t address_len, int *port) {
    if (c == NULL || c->listen_fd < 0) return PPC_ERR_INVALID;
    if (address) snprintf(address, address_len, "%s", c->local_address);
    if (port) *port = c->local_port;
    return PPC_OK;
}

void ppc_connector_stop(ppc_connector *c) {
    if (c == NULL) return;
    if (atomic_exchange(&c->stop, true)) return;
    if (c->stop_pipe[1] >= 0) { ssize_t n = write(c->stop_pipe[1], "x", 1); (void)n; }
    pthread_mutex_lock(&c->lock);
    for (ppc_conn *conn = c->conns; conn; conn = conn->next) conn_shutdown(conn);
    for (pending *p = c->pendings; p; p = p->next) if (!p->done) { p->done = true; p->error = PPC_ERR_STOPPED; }
    pthread_cond_broadcast(&c->cond);
    pthread_mutex_unlock(&c->lock);
    if (c->accepting) { pthread_join(c->accept_thread, NULL); c->accepting = false; }
    if (c->listen_fd >= 0) { close(c->listen_fd); c->listen_fd = -1; }
    reap(c, true);
}

void ppc_connector_free(ppc_connector *c) {
    if (c == NULL) return;
    ppc_connector_stop(c);
    while (c->peers) { ppc_peer *p = c->peers; c->peers = p->next; peer_free(p); }
    while (c->retired) { ppc_peer *p = c->retired; c->retired = p->next; peer_free(p); }
    while (c->handlers) { handler *h = c->handlers; c->handlers = h->next; free(h); }
    while (c->pendings) { pending *p = c->pendings; c->pendings = p->next; free(p->payload); free(p); }
    if (c->stop_pipe[0] >= 0) close(c->stop_pipe[0]);
    if (c->stop_pipe[1] >= 0) close(c->stop_pipe[1]);
    ppc_tls_ctx_free(c->tls_server);
    ppc_tls_ctx_free(c->tls_client);
    pthread_mutex_destroy(&c->lock);
    pthread_cond_destroy(&c->cond);
    free(c->name);
    free(c->inbound_address);
    free(c->cipher);
    free(c);
}
