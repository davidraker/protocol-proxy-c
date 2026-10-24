/* Log records from launched proxies (section 9): a JSON line on a pipe, an entry of a LOG batch, or a plain line,
 * rebuilt as the manager handles them. */
#include "internal.h"

#include <ctype.h>
#include <stdio.h>

static int syslog_level(char digit) {
    switch (digit) {
    case '7': return PPC_LOG_DEBUG;
    case '6': case '5': return PPC_LOG_INFO;
    case '4': return PPC_LOG_WARNING;
    case '3': return PPC_LOG_ERROR;
    case '2': case '1': case '0': return PPC_LOG_CRITICAL;
    default: return -1;
    }
}

char *ppc_proxy_logger_name(const char *manifest_name, const char *proxy_name) {
    ppc_buf b = {0};
    ppc_buf_append(&b, PPC_PROXIES_LOGGER ".", strlen(PPC_PROXIES_LOGGER) + 1);
    ppc_buf_append(&b, manifest_name, strlen(manifest_name));
    ppc_buf_append(&b, ".", 1);
    size_t start = b.len;
    bool pending_sep = false;
    for (const char *p = proxy_name ? proxy_name : ""; *p; p++) {
        if (isalnum((unsigned char)*p) || *p == '-') {
            if (pending_sep && b.len > start) ppc_buf_append(&b, "_", 1);
            pending_sep = false;
            ppc_buf_append(&b, p, 1);
        } else {
            pending_sep = true;
        }
    }
    if (b.len == start) ppc_buf_append(&b, "proxy", 5);
    ppc_buf_append(&b, "", 1);
    return (char *)b.data;
}

static int set_strings(ppc_record *out, const char *logger, const char *channel, const char *proxy_name, int pid) {
    out->logger = ppc_strdup(logger ? logger : "");
    out->channel = ppc_strdup(channel ? channel : "");
    out->proxy_name = ppc_strdup(proxy_name ? proxy_name : "");
    out->pid = pid;
    return out->logger && out->channel && out->proxy_name ? PPC_OK : PPC_ERR_NOMEM;
}

int ppc_record_from_fields(const ppc_json *fields, const char *logger, const char *channel, int pid,
                           const char *proxy_name, ppc_record *out) {
    if (fields == NULL || fields->type != PPC_JSON_OBJECT || out == NULL) return PPC_ERR_INVALID;
    memset(out, 0, sizeof *out);
    if (set_strings(out, logger, channel, proxy_name, pid) != PPC_OK) { ppc_record_free(out); return PPC_ERR_NOMEM; }
    out->fields = ppc_json_clone(fields);
    out->remote_name = ppc_strdup(ppc_json_get_string(fields, "name", ""));
    const ppc_json *msg = ppc_json_get(fields, "msg");
    if (msg == NULL || msg->type == PPC_JSON_NULL) out->msg = ppc_strdup("");
    else if (msg->type == PPC_JSON_STRING) out->msg = ppc_strdup(msg->string);
    else out->msg = ppc_json_dump(msg);
    const char *exc = ppc_json_get_string(fields, "exc_text", NULL);
    if (exc) out->exc_text = ppc_strdup(exc);
    const ppc_json *levelno = ppc_json_get(fields, "levelno");
    if (levelno && levelno->type == PPC_JSON_NUMBER) out->level = (int)levelno->number;
    else {
        int by_name = ppc_log_level_from_name(ppc_json_get_string(fields, "levelname", ""));
        out->level = by_name >= 0 ? by_name : PPC_LOG_INFO;
    }
    const ppc_json *process = ppc_json_get(fields, "process");
    if (process && process->type == PPC_JSON_NUMBER && process->number != 0) out->pid = (int)process->number;
    if (out->fields == NULL || out->remote_name == NULL || out->msg == NULL) { ppc_record_free(out); return PPC_ERR_NOMEM; }
    return PPC_OK;
}

int ppc_record_from_line(const char *line, size_t len, const char *logger, const char *stream, int pid,
                         const char *proxy_name, ppc_record *out) {
    if (line == NULL || out == NULL) return PPC_ERR_INVALID;
    while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) len--;
    size_t lead = 0;
    while (lead < len && isspace((unsigned char)line[lead])) lead++;
    if (lead == len) return 0;
    if (line[0] == '{' && line[len - 1] == '}') {
        char err[64];
        ppc_json *fields = ppc_json_parse(line, len, err, sizeof err);
        if (fields && fields->type == PPC_JSON_OBJECT && ppc_json_get(fields, "msg") != NULL) {
            int rc = ppc_record_from_fields(fields, logger, stream, pid, proxy_name, out);
            ppc_json_free(fields);
            return rc == PPC_OK ? 1 : rc;
        }
        ppc_json_free(fields);
    }
    memset(out, 0, sizeof *out);
    if (set_strings(out, logger, stream, proxy_name, pid) != PPC_OK) { ppc_record_free(out); return PPC_ERR_NOMEM; }
    out->level = stream && strcmp(stream, "stdout") == 0 ? PPC_LOG_INFO : PPC_LOG_WARNING;
    if (len > 2 && line[0] == '<' && line[2] == '>' && isdigit((unsigned char)line[1])) {
        int level = syslog_level(line[1]);
        if (level >= 0) out->level = level;
        line += 3;
        len -= 3;
    }
    out->remote_name = ppc_strdup(stream ? stream : "");
    out->msg = malloc(len + 1);
    if (out->msg) { memcpy(out->msg, line, len); out->msg[len] = '\0'; }
    if (out->remote_name == NULL || out->msg == NULL) { ppc_record_free(out); return PPC_ERR_NOMEM; }
    return 1;
}

int ppc_records_from_batch(const char *payload, size_t len, const char *logger, int pid, const char *proxy_name,
                           ppc_record **out, size_t *count) {
    if (out == NULL || count == NULL) return PPC_ERR_INVALID;
    *out = NULL;
    *count = 0;
    char err[64];
    ppc_json *batch = ppc_json_parse(payload, len, err, sizeof err);
    if (batch == NULL || batch->type != PPC_JSON_OBJECT) { ppc_json_free(batch); return PPC_ERR_INVALID; }
    const ppc_json *records = ppc_json_get(batch, "records");
    size_t n = records && records->type == PPC_JSON_ARRAY ? records->count : 0;
    long dropped = (long)ppc_json_get_number(batch, "dropped", 0);
    ppc_record *list = calloc(n + 1, sizeof *list);
    if (list == NULL) { ppc_json_free(batch); return PPC_ERR_NOMEM; }
    size_t made = 0;
    for (size_t i = 0; i < n; i++)
        if (ppc_record_from_fields(records->items[i], logger, "socket", pid, proxy_name, &list[made]) == PPC_OK) made++;
    if (dropped > 0) {
        ppc_record *r = &list[made];
        memset(r, 0, sizeof *r);
        if (set_strings(r, logger, "socket", proxy_name, pid) == PPC_OK) {
            r->level = PPC_LOG_WARNING;
            r->remote_name = ppc_strdup("protocol_proxy.logs");
            char text[256];
            snprintf(text, sizeof text, "%s dropped %ld log records (rate or queue limit).", proxy_name ? proxy_name : logger, dropped);
            r->msg = ppc_strdup(text);
            if (r->remote_name && r->msg) made++;
            else ppc_record_free(r);
        }
    }
    ppc_json_free(batch);
    *out = list;
    *count = made;
    return PPC_OK;
}

int ppc_record_copy(const ppc_record *in, ppc_record *out) {
    if (in == NULL || out == NULL) return PPC_ERR_INVALID;
    memset(out, 0, sizeof *out);
    out->logger = ppc_strdup(in->logger ? in->logger : "");
    out->remote_name = ppc_strdup(in->remote_name ? in->remote_name : "");
    out->channel = ppc_strdup(in->channel ? in->channel : "");
    out->msg = ppc_strdup(in->msg ? in->msg : "");
    out->proxy_name = ppc_strdup(in->proxy_name ? in->proxy_name : "");
    out->exc_text = in->exc_text ? ppc_strdup(in->exc_text) : NULL;
    out->fields = in->fields ? ppc_json_clone(in->fields) : NULL;
    out->level = in->level;
    out->pid = in->pid;
    if (out->logger == NULL || out->remote_name == NULL || out->channel == NULL || out->msg == NULL || out->proxy_name == NULL
        || (in->exc_text && out->exc_text == NULL) || (in->fields && out->fields == NULL)) { ppc_record_free(out); return PPC_ERR_NOMEM; }
    return PPC_OK;
}

void ppc_record_free(ppc_record *r) {
    if (r == NULL) return;
    free(r->logger);
    free(r->remote_name);
    free(r->channel);
    free(r->msg);
    free(r->exc_text);
    free(r->proxy_name);
    ppc_json_free(r->fields);
    memset(r, 0, sizeof *r);
}

void ppc_record_log(const ppc_record *record, void *user) {
    (void)user;
    if (record == NULL) return;
    const char *remote = record->remote_name ? record->remote_name : "";
    bool tagged = remote[0] && (record->channel == NULL || strcmp(remote, record->channel) != 0);
    if (record->exc_text)
        ppc_log(record->level, record->logger, "<proxy>", 0, "", "%s%s%s%s\n%s", tagged ? "[" : "", tagged ? remote : "",
                tagged ? "] " : "", record->msg ? record->msg : "", record->exc_text);
    else
        ppc_log(record->level, record->logger, "<proxy>", 0, "", "%s%s%s%s", tagged ? "[" : "", tagged ? remote : "",
                tagged ? "] " : "", record->msg ? record->msg : "");
}
