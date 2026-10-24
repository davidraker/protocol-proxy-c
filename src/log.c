/* Log records (section 9): one JSON object per line on stderr with Python LogRecord attribute names when launched
 * by a manager (and stderr is a pipe), readable text otherwise. Thread-safe; each record is one write(2).
 * After registration a proxy may install a queue (ppc_log_set_queue): JSON records are then held for LOG batches over
 * the socket instead of being written, bounded and rate limited, with drops counted. */
#include "internal.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static int current_level = PPC_LOG_INFO;
static bool json_mode = false;
static bool initialized = false;
static double started_at = 0;
static char process_name[128] = "echo-proxy";
static ppc_log_queue *active_queue = NULL;      /* under log_lock */

struct ppc_log_queue {
    pthread_mutex_t lock;
    char **records;
    size_t len, cap, max_len;
    double rate;                /* records per second sustained */
    double burst;               /* bucket capacity */
    double tokens;
    double refilled;            /* monotonic time of the last refill */
    long dropped;               /* since the last drain */
    long total_dropped;
};

static bool is_pipe(int fd) {
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISFIFO(st.st_mode);
}

int ppc_log_level_from_name(const char *name) {
    if (name == NULL) return -1;
    char upper[32];
    size_t n = strlen(name);
    if (n == 0 || n >= sizeof upper) return -1;
    bool digits = true;
    for (size_t i = 0; i < n; i++) {
        upper[i] = (char)toupper((unsigned char)name[i]);
        if (name[i] < '0' || name[i] > '9') digits = false;
    }
    upper[n] = '\0';
    if (digits) return atoi(upper);
    if (strcmp(upper, "DEBUG") == 0) return PPC_LOG_DEBUG;
    if (strcmp(upper, "INFO") == 0) return PPC_LOG_INFO;
    if (strcmp(upper, "WARNING") == 0 || strcmp(upper, "WARN") == 0) return PPC_LOG_WARNING;
    if (strcmp(upper, "ERROR") == 0) return PPC_LOG_ERROR;
    if (strcmp(upper, "CRITICAL") == 0 || strcmp(upper, "FATAL") == 0) return PPC_LOG_CRITICAL;
    if (strcmp(upper, "NOTSET") == 0) return 0;
    return -1;
}

const char *ppc_log_level_name(int level) {
    /* Python's getLevelName: exact names for the standard levels, "Level N" otherwise. */
    static __thread char other[24];
    switch (level) {
    case 0: return "NOTSET";
    case PPC_LOG_DEBUG: return "DEBUG";
    case PPC_LOG_INFO: return "INFO";
    case PPC_LOG_WARNING: return "WARNING";
    case PPC_LOG_ERROR: return "ERROR";
    case PPC_LOG_CRITICAL: return "CRITICAL";
    default:
        snprintf(other, sizeof other, "Level %d", level);
        return other;
    }
}

void ppc_log_init(const char *level_name, int json_lines, const char *name) {
    pthread_mutex_lock(&log_lock);
    const char *env_level = getenv("PROTOCOL_PROXY_LOG_LEVEL");
    int level = ppc_log_level_from_name(level_name ? level_name : env_level);
    current_level = level >= 0 ? level : PPC_LOG_INFO;
    if (json_lines < 0)
        json_mode = getenv("_LAUNCHED_BY_PROXY_MANAGER") != NULL && is_pipe(STDERR_FILENO);
    else
        json_mode = json_lines != 0;
    if (name) snprintf(process_name, sizeof process_name, "%s", name);
    started_at = ppc_now();
    initialized = true;
    pthread_mutex_unlock(&log_lock);
}

int ppc_log_level(void) { return current_level; }
void ppc_log_set_level(int level) { current_level = level; }
bool ppc_log_json_mode(void) { return json_mode; }

/* ---- the LOG queue -------------------------------------------------------------------------------------------- */
ppc_log_queue *ppc_log_queue_new(size_t max_len, double rate, int burst) {
    ppc_log_queue *q = calloc(1, sizeof *q);
    if (q == NULL) return NULL;
    pthread_mutex_init(&q->lock, NULL);
    q->max_len = max_len ? max_len : PPC_LOG_QUEUE_MAX;
    q->rate = rate > 0 ? rate : PPC_LOG_QUEUE_RATE;
    q->burst = burst > 0 ? burst : PPC_LOG_QUEUE_BURST;
    q->tokens = q->burst;
    q->refilled = ppc_monotonic();
    return q;
}

void ppc_log_queue_free(ppc_log_queue *q) {
    if (q == NULL) return;
    for (size_t i = 0; i < q->len; i++) free(q->records[i]);
    free(q->records);
    pthread_mutex_destroy(&q->lock);
    free(q);
}

/* Under q->lock: the token bucket of section 11a. */
static bool take_token(ppc_log_queue *q) {
    double now = ppc_monotonic();
    q->tokens += (now - q->refilled) * q->rate;
    if (q->tokens > q->burst) q->tokens = q->burst;
    q->refilled = now;
    if (q->tokens >= 1.0) { q->tokens -= 1.0; return true; }
    return false;
}

bool ppc_log_queue_push(ppc_log_queue *q, char *record) {
    if (q == NULL || record == NULL) { free(record); return false; }
    pthread_mutex_lock(&q->lock);
    bool admitted = q->len < q->max_len && take_token(q);
    if (admitted && q->len == q->cap) {
        size_t cap = q->cap ? q->cap * 2 : 64;
        if (cap > q->max_len) cap = q->max_len;
        char **grown = realloc(q->records, cap * sizeof *grown);
        if (grown == NULL) admitted = false;
        else { q->records = grown; q->cap = cap; }
    }
    if (admitted) q->records[q->len++] = record;
    else { q->dropped++; q->total_dropped++; free(record); }
    pthread_mutex_unlock(&q->lock);
    return admitted;
}

size_t ppc_log_queue_len(ppc_log_queue *q) {
    if (q == NULL) return 0;
    pthread_mutex_lock(&q->lock);
    size_t n = q->len;
    pthread_mutex_unlock(&q->lock);
    return n;
}

long ppc_log_queue_total_dropped(ppc_log_queue *q) {
    if (q == NULL) return 0;
    pthread_mutex_lock(&q->lock);
    long n = q->total_dropped;
    pthread_mutex_unlock(&q->lock);
    return n;
}

char **ppc_log_queue_drain(ppc_log_queue *q, size_t limit, size_t *count, long *dropped) {
    *count = 0;
    *dropped = 0;
    if (q == NULL) return NULL;
    pthread_mutex_lock(&q->lock);
    size_t n = limit && limit < q->len ? limit : q->len;
    char **taken = NULL;
    if (n) {
        taken = malloc(n * sizeof *taken);
        if (taken == NULL) n = 0;       /* leave the records queued for the next drain */
        else {
            memcpy(taken, q->records, n * sizeof *taken);
            memmove(q->records, q->records + n, (q->len - n) * sizeof *taken);
            q->len -= n;
        }
    }
    *count = n;
    *dropped = q->dropped;
    q->dropped = 0;
    pthread_mutex_unlock(&q->lock);
    return taken;
}

char *ppc_log_batch_json(char *const *records, size_t count, long dropped) {
    /* The records are JSON objects already; join them as Python's json.dumps would. */
    size_t total = 32 + 24;
    for (size_t i = 0; i < count; i++) total += strlen(records[i]) + 2;
    char *out = malloc(total);
    if (out == NULL) return NULL;
    char *w = out;
    w += sprintf(w, "{\"records\": [");
    for (size_t i = 0; i < count; i++) {
        size_t n = strlen(records[i]);
        if (i) { *w++ = ','; *w++ = ' '; }
        memcpy(w, records[i], n);
        w += n;
    }
    sprintf(w, "], \"dropped\": %ld}", dropped);
    return out;
}

void ppc_log_set_queue(ppc_log_queue *q) {
    pthread_mutex_lock(&log_lock);
    active_queue = q;
    pthread_mutex_unlock(&log_lock);
}

static const char *basename_of(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

char *ppc_log_record_json(int level, const char *logger, const char *file, int line, const char *func, const char *msg) {
    double now = ppc_now();
    const char *filename = basename_of(file ? file : "");
    char module[128];
    snprintf(module, sizeof module, "%s", filename);
    char *dot = strrchr(module, '.');
    if (dot) *dot = '\0';
    ppc_json *o = ppc_json_new_object();
    if (o == NULL) return NULL;
    ppc_json_object_set(o, "name", ppc_json_new_string(logger ? logger : PPC_LOGGER));
    ppc_json_object_set(o, "msg", ppc_json_new_string(msg ? msg : ""));
    ppc_json_object_set(o, "levelname", ppc_json_new_string(ppc_log_level_name(level)));
    ppc_json_object_set(o, "levelno", ppc_json_new_integer(level));
    ppc_json_object_set(o, "pathname", ppc_json_new_string(file ? file : ""));
    ppc_json_object_set(o, "filename", ppc_json_new_string(filename));
    ppc_json_object_set(o, "module", ppc_json_new_string(module));
    ppc_json_object_set(o, "exc_text", ppc_json_new_null());
    ppc_json_object_set(o, "stack_info", ppc_json_new_null());
    ppc_json_object_set(o, "lineno", ppc_json_new_integer(line));
    ppc_json_object_set(o, "funcName", ppc_json_new_string(func ? func : ""));
    ppc_json_object_set(o, "created", ppc_json_new_number(now));
    ppc_json_object_set(o, "msecs", ppc_json_new_number((double)((long long)(now * 1000) % 1000)));
    ppc_json_object_set(o, "relativeCreated", ppc_json_new_number((now - (started_at ? started_at : now)) * 1000.0));
    ppc_json_object_set(o, "thread", ppc_json_new_integer((long long)syscall(SYS_gettid)));
    ppc_json_object_set(o, "threadName", ppc_json_new_string("MainThread"));
    ppc_json_object_set(o, "processName", ppc_json_new_string(process_name));
    ppc_json_object_set(o, "process", ppc_json_new_integer((long long)getpid()));
    ppc_json_object_set(o, "taskName", ppc_json_new_null());
    char *text = ppc_json_dump(o);
    ppc_json_free(o);
    return text;
}

static void write_all(int fd, const char *data, size_t len) {
    while (len) {
        ssize_t n = write(fd, data, len);
        if (n < 0) { if (errno == EINTR) continue; return; }
        data += n;
        len -= (size_t)n;
    }
}

void ppc_log_write_json_line(const char *record) {
    size_t n = strlen(record);
    char *out = malloc(n + 2);
    if (out == NULL) return;
    memcpy(out, record, n);
    out[n] = '\n';
    out[n + 1] = '\0';
    pthread_mutex_lock(&log_lock);
    write_all(STDERR_FILENO, out, n + 1);
    pthread_mutex_unlock(&log_lock);
    free(out);
}

void ppc_log(int level, const char *logger, const char *file, int line, const char *func, const char *fmt, ...) {
    if (level < current_level) return;
    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    char *out;
    if (json_mode) {
        char *record = ppc_log_record_json(level, logger, file, line, func, msg);
        if (record == NULL) return;
        pthread_mutex_lock(&log_lock);
        if (active_queue) {             /* queued for the next LOG batch; the queue frees or keeps the record */
            ppc_log_queue_push(active_queue, record);
            pthread_mutex_unlock(&log_lock);
            return;
        }
        pthread_mutex_unlock(&log_lock);
        size_t n = strlen(record);
        out = malloc(n + 2);
        if (out == NULL) { free(record); return; }
        memcpy(out, record, n);
        out[n] = '\n';
        out[n + 1] = '\0';
        free(record);
    } else {
        double now = ppc_now();
        time_t secs = (time_t)now;
        struct tm tm;
        localtime_r(&secs, &tm);
        char stamp[32];
        strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M:%S", &tm);
        size_t n = strlen(msg) + 128 + strlen(logger ? logger : "");
        out = malloc(n);
        if (out == NULL) return;
        snprintf(out, n, "%s,%03d %s %s: %s\n", stamp, (int)((now - (double)secs) * 1000), logger ? logger : PPC_LOGGER,
                 ppc_log_level_name(level), msg);
    }
    pthread_mutex_lock(&log_lock);
    write_all(STDERR_FILENO, out, strlen(out));
    pthread_mutex_unlock(&log_lock);
    free(out);
}
