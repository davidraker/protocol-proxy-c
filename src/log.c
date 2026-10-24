/* Log records (section 9): one JSON object per line on stderr with Python LogRecord attribute names when launched
 * by a manager (and stderr is a pipe), readable text otherwise. Thread-safe; each record is one write(2). */
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
