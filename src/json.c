/* A small JSON parser and writer: what the protocol needs (registration payload and reply, PING reply, error
 * replies, SET_LOG_LEVEL, TLS material, log records). The writer follows Python's json.dumps defaults: ", " and ": "
 * separators, non-ASCII escaped as \uXXXX, floats in their shortest round-trip form. */
#include "internal.h"

#include <math.h>
#include <stdio.h>

#define MAX_DEPTH 256

/* ---- construction --------------------------------------------------------------------------------------------- */
static ppc_json *new_value(ppc_json_type type) {
    ppc_json *v = calloc(1, sizeof *v);
    if (v) v->type = type;
    return v;
}

ppc_json *ppc_json_new_null(void) { return new_value(PPC_JSON_NULL); }
ppc_json *ppc_json_new_bool(bool b) { ppc_json *v = new_value(PPC_JSON_BOOL); if (v) v->boolean = b; return v; }
ppc_json *ppc_json_new_number(double d) { ppc_json *v = new_value(PPC_JSON_NUMBER); if (v) v->number = d; return v; }
ppc_json *ppc_json_new_integer(long long i) {
    ppc_json *v = new_value(PPC_JSON_NUMBER);
    if (v) { v->number = (double)i; v->integer = i; v->is_integer = true; }
    return v;
}
ppc_json *ppc_json_new_string(const char *s) {
    ppc_json *v = new_value(PPC_JSON_STRING);
    if (v == NULL) return NULL;
    v->string = ppc_strdup(s ? s : "");
    if (v->string == NULL) { free(v); return NULL; }
    return v;
}
ppc_json *ppc_json_new_array(void) { return new_value(PPC_JSON_ARRAY); }
ppc_json *ppc_json_new_object(void) { return new_value(PPC_JSON_OBJECT); }

void ppc_json_free(ppc_json *v) {
    if (v == NULL) return;
    free(v->string);
    for (size_t i = 0; i < v->count; i++) {
        ppc_json_free(v->items[i]);
        if (v->keys) free(v->keys[i]);
    }
    free(v->items);
    free(v->keys);
    free(v);
}

static int grow(ppc_json *v) {
    size_t cap = v->count + 1;
    ppc_json **items = realloc(v->items, cap * sizeof *items);
    if (items == NULL) return PPC_ERR_NOMEM;
    v->items = items;
    if (v->type == PPC_JSON_OBJECT) {
        char **keys = realloc(v->keys, cap * sizeof *keys);
        if (keys == NULL) return PPC_ERR_NOMEM;
        v->keys = keys;
    }
    return PPC_OK;
}

int ppc_json_object_set(ppc_json *object, const char *key, ppc_json *value) {
    if (object == NULL || object->type != PPC_JSON_OBJECT || key == NULL) { ppc_json_free(value); return PPC_ERR_INVALID; }
    if (value == NULL) return PPC_ERR_NOMEM;
    for (size_t i = 0; i < object->count; i++) {
        if (strcmp(object->keys[i], key) == 0) {
            ppc_json_free(object->items[i]);
            object->items[i] = value;
            return PPC_OK;
        }
    }
    char *k = ppc_strdup(key);
    if (k == NULL || grow(object) != PPC_OK) { free(k); ppc_json_free(value); return PPC_ERR_NOMEM; }
    object->keys[object->count] = k;
    object->items[object->count] = value;
    object->count++;
    return PPC_OK;
}

int ppc_json_array_append(ppc_json *array, ppc_json *value) {
    if (array == NULL || array->type != PPC_JSON_ARRAY) { ppc_json_free(value); return PPC_ERR_INVALID; }
    if (value == NULL) return PPC_ERR_NOMEM;
    if (grow(array) != PPC_OK) { ppc_json_free(value); return PPC_ERR_NOMEM; }
    array->items[array->count++] = value;
    return PPC_OK;
}

const ppc_json *ppc_json_get(const ppc_json *object, const char *key) {
    if (object == NULL || object->type != PPC_JSON_OBJECT || key == NULL) return NULL;
    for (size_t i = 0; i < object->count; i++)
        if (strcmp(object->keys[i], key) == 0) return object->items[i];
    return NULL;
}

const char *ppc_json_get_string(const ppc_json *object, const char *key, const char *dflt) {
    const ppc_json *v = ppc_json_get(object, key);
    return v && v->type == PPC_JSON_STRING ? v->string : dflt;
}

bool ppc_json_get_bool(const ppc_json *object, const char *key, bool dflt) {
    const ppc_json *v = ppc_json_get(object, key);
    return v && v->type == PPC_JSON_BOOL ? v->boolean : dflt;
}

double ppc_json_get_number(const ppc_json *object, const char *key, double dflt) {
    const ppc_json *v = ppc_json_get(object, key);
    return v && v->type == PPC_JSON_NUMBER ? v->number : dflt;
}

/* ---- parser -------------------------------------------------------------------------------------------------- */
typedef struct {
    const char *start, *p, *end;
    char *err;
    size_t err_len;
    int depth;
} parser;

static void fail(parser *ps, const char *what) {
    if (ps->err && ps->err_len) snprintf(ps->err, ps->err_len, "%s at offset %ld", what, (long)(ps->p - ps->start));
}

static void skip_ws(parser *ps) {
    while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r')) ps->p++;
}

static int utf8_put(ppc_buf *b, uint32_t cp) {
    uint8_t out[4];
    size_t n;
    if (cp < 0x80) { out[0] = (uint8_t)cp; n = 1; }
    else if (cp < 0x800) { out[0] = (uint8_t)(0xC0 | (cp >> 6)); out[1] = (uint8_t)(0x80 | (cp & 63)); n = 2; }
    else if (cp < 0x10000) {
        out[0] = (uint8_t)(0xE0 | (cp >> 12)); out[1] = (uint8_t)(0x80 | ((cp >> 6) & 63)); out[2] = (uint8_t)(0x80 | (cp & 63)); n = 3;
    } else {
        out[0] = (uint8_t)(0xF0 | (cp >> 18)); out[1] = (uint8_t)(0x80 | ((cp >> 12) & 63));
        out[2] = (uint8_t)(0x80 | ((cp >> 6) & 63)); out[3] = (uint8_t)(0x80 | (cp & 63)); n = 4;
    }
    return ppc_buf_append(b, out, n);
}

static int hex4(parser *ps, uint32_t *out) {
    if (ps->end - ps->p < 4) return -1;
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        char c = ps->p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (uint32_t)(c - 'A' + 10);
        else return -1;
    }
    ps->p += 4;
    *out = v;
    return 0;
}

static char *parse_string_raw(parser *ps) {
    if (ps->p >= ps->end || *ps->p != '"') { fail(ps, "expected string"); return NULL; }
    ps->p++;
    ppc_buf b = {0};
    while (ps->p < ps->end) {
        unsigned char c = (unsigned char)*ps->p++;
        if (c == '"') {
            if (ppc_buf_append(&b, "", 1) != PPC_OK) { ppc_buf_free(&b); return NULL; }
            return (char *)b.data;
        }
        if (c == '\\') {
            if (ps->p >= ps->end) break;
            char e = *ps->p++;
            int rc = PPC_OK;
            switch (e) {
            case '"': rc = ppc_buf_append(&b, "\"", 1); break;
            case '\\': rc = ppc_buf_append(&b, "\\", 1); break;
            case '/': rc = ppc_buf_append(&b, "/", 1); break;
            case 'b': rc = ppc_buf_append(&b, "\b", 1); break;
            case 'f': rc = ppc_buf_append(&b, "\f", 1); break;
            case 'n': rc = ppc_buf_append(&b, "\n", 1); break;
            case 'r': rc = ppc_buf_append(&b, "\r", 1); break;
            case 't': rc = ppc_buf_append(&b, "\t", 1); break;
            case 'u': {
                uint32_t cp;
                if (hex4(ps, &cp) != 0) { fail(ps, "bad \\u escape"); ppc_buf_free(&b); return NULL; }
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    uint32_t lo;
                    if (ps->end - ps->p >= 6 && ps->p[0] == '\\' && ps->p[1] == 'u') {
                        ps->p += 2;
                        if (hex4(ps, &lo) != 0 || lo < 0xDC00 || lo > 0xDFFF) { fail(ps, "bad surrogate pair"); ppc_buf_free(&b); return NULL; }
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                }
                rc = utf8_put(&b, cp);
                break;
            }
            default: fail(ps, "bad escape"); ppc_buf_free(&b); return NULL;
            }
            if (rc != PPC_OK) { ppc_buf_free(&b); return NULL; }
            continue;
        }
        if (c < 0x20) { fail(ps, "control character in string"); ppc_buf_free(&b); return NULL; }
        if (ppc_buf_append(&b, &c, 1) != PPC_OK) { ppc_buf_free(&b); return NULL; }
    }
    fail(ps, "unterminated string");
    ppc_buf_free(&b);
    return NULL;
}

static ppc_json *parse_value(parser *ps);

static ppc_json *parse_number(parser *ps) {
    const char *start = ps->p;
    bool integral = true;
    if (ps->p < ps->end && *ps->p == '-') ps->p++;
    while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    if (ps->p < ps->end && *ps->p == '.') { integral = false; ps->p++; while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++; }
    if (ps->p < ps->end && (*ps->p == 'e' || *ps->p == 'E')) {
        integral = false; ps->p++;
        if (ps->p < ps->end && (*ps->p == '+' || *ps->p == '-')) ps->p++;
        while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    }
    size_t n = (size_t)(ps->p - start);
    if (n == 0 || n > 64) { fail(ps, "bad number"); return NULL; }
    char tmp[65];
    memcpy(tmp, start, n);
    tmp[n] = '\0';
    char *endp;
    errno = 0;
    double d = strtod(tmp, &endp);
    if (endp != tmp + n) { fail(ps, "bad number"); return NULL; }
    ppc_json *v = ppc_json_new_number(d);
    if (v == NULL) return NULL;
    if (integral) {
        errno = 0;
        long long i = strtoll(tmp, &endp, 10);
        if (errno == 0 && endp == tmp + n) { v->is_integer = true; v->integer = i; }
    }
    return v;
}

static bool match(parser *ps, const char *word) {
    size_t n = strlen(word);
    if ((size_t)(ps->end - ps->p) >= n && memcmp(ps->p, word, n) == 0) { ps->p += n; return true; }
    return false;
}

static ppc_json *parse_value(parser *ps) {
    skip_ws(ps);
    if (ps->p >= ps->end) { fail(ps, "unexpected end"); return NULL; }
    if (++ps->depth > MAX_DEPTH) { fail(ps, "too deeply nested"); return NULL; }
    ppc_json *v = NULL;
    char c = *ps->p;
    if (c == '{') {
        ps->p++;
        v = ppc_json_new_object();
        if (v == NULL) return NULL;
        skip_ws(ps);
        if (ps->p < ps->end && *ps->p == '}') { ps->p++; }
        else for (;;) {
            skip_ws(ps);
            char *key = parse_string_raw(ps);
            if (key == NULL) { ppc_json_free(v); return NULL; }
            skip_ws(ps);
            if (ps->p >= ps->end || *ps->p != ':') { fail(ps, "expected ':'"); free(key); ppc_json_free(v); return NULL; }
            ps->p++;
            ppc_json *item = parse_value(ps);
            if (item == NULL) { free(key); ppc_json_free(v); return NULL; }
            if (ppc_json_object_set(v, key, item) != PPC_OK) { free(key); ppc_json_free(v); return NULL; }
            free(key);
            skip_ws(ps);
            if (ps->p < ps->end && *ps->p == ',') { ps->p++; continue; }
            if (ps->p < ps->end && *ps->p == '}') { ps->p++; break; }
            fail(ps, "expected ',' or '}'"); ppc_json_free(v); return NULL;
        }
    } else if (c == '[') {
        ps->p++;
        v = ppc_json_new_array();
        if (v == NULL) return NULL;
        skip_ws(ps);
        if (ps->p < ps->end && *ps->p == ']') { ps->p++; }
        else for (;;) {
            ppc_json *item = parse_value(ps);
            if (item == NULL) { ppc_json_free(v); return NULL; }
            if (ppc_json_array_append(v, item) != PPC_OK) { ppc_json_free(v); return NULL; }
            skip_ws(ps);
            if (ps->p < ps->end && *ps->p == ',') { ps->p++; continue; }
            if (ps->p < ps->end && *ps->p == ']') { ps->p++; break; }
            fail(ps, "expected ',' or ']'"); ppc_json_free(v); return NULL;
        }
    } else if (c == '"') {
        char *s = parse_string_raw(ps);
        if (s == NULL) return NULL;
        v = new_value(PPC_JSON_STRING);
        if (v == NULL) { free(s); return NULL; }
        v->string = s;
    } else if (match(ps, "true")) {
        v = ppc_json_new_bool(true);
    } else if (match(ps, "false")) {
        v = ppc_json_new_bool(false);
    } else if (match(ps, "null")) {
        v = ppc_json_new_null();
    } else if (c == '-' || (c >= '0' && c <= '9')) {
        v = parse_number(ps);
    } else {
        fail(ps, "unexpected character");
        return NULL;
    }
    ps->depth--;
    return v;
}

ppc_json *ppc_json_parse(const char *text, size_t len, char *err, size_t err_len) {
    if (err && err_len) err[0] = '\0';
    if (text == NULL) { if (err && err_len) snprintf(err, err_len, "no text"); return NULL; }
    parser ps = { text, text, text + len, err, err_len, 0 };
    ppc_json *v = parse_value(&ps);
    if (v == NULL) return NULL;
    skip_ws(&ps);
    if (ps.p != ps.end) { fail(&ps, "trailing data"); ppc_json_free(v); return NULL; }
    return v;
}

/* ---- writer -------------------------------------------------------------------------------------------------- */
static int dump_string(ppc_buf *b, const char *s) {
    if (ppc_buf_append(b, "\"", 1) != PPC_OK) return PPC_ERR_NOMEM;
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        unsigned char c = *p;
        char esc[13];
        int rc;
        if (c == '"') rc = ppc_buf_append(b, "\\\"", 2);
        else if (c == '\\') rc = ppc_buf_append(b, "\\\\", 2);
        else if (c == '\n') rc = ppc_buf_append(b, "\\n", 2);
        else if (c == '\r') rc = ppc_buf_append(b, "\\r", 2);
        else if (c == '\t') rc = ppc_buf_append(b, "\\t", 2);
        else if (c == '\b') rc = ppc_buf_append(b, "\\b", 2);
        else if (c == '\f') rc = ppc_buf_append(b, "\\f", 2);
        else if (c >= 0x20 && c < 0x7f) rc = ppc_buf_append(b, &c, 1);
        else if (c < 0x80) { snprintf(esc, sizeof esc, "\\u%04x", c); rc = ppc_buf_append(b, esc, 6); }
        else {
            /* Decode one UTF-8 sequence; invalid bytes are written as U+FFFD. */
            uint32_t cp; int n;
            if ((c & 0xE0) == 0xC0 && (p[1] & 0xC0) == 0x80) { cp = ((c & 0x1F) << 6) | (p[1] & 0x3F); n = 2; }
            else if ((c & 0xF0) == 0xE0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
                cp = ((c & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F); n = 3;
            } else if ((c & 0xF8) == 0xF0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80) {
                cp = ((uint32_t)(c & 0x07) << 18) | ((uint32_t)(p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F); n = 4;
            } else { cp = 0xFFFD; n = 1; }
            if (cp >= 0x10000) {
                uint32_t u = cp - 0x10000;
                snprintf(esc, sizeof esc, "\\u%04x\\u%04x", 0xD800 + (u >> 10), 0xDC00 + (u & 0x3FF));
                rc = ppc_buf_append(b, esc, 12);
            } else {
                snprintf(esc, sizeof esc, "\\u%04x", cp);
                rc = ppc_buf_append(b, esc, 6);
            }
            p += n;
            if (rc != PPC_OK) return rc;
            continue;
        }
        if (rc != PPC_OK) return rc;
        p++;
    }
    return ppc_buf_append(b, "\"", 1);
}

/* Python's repr(float): the shortest digit string that round-trips, written positionally when the decimal point
 * falls within (-4, 16] digits of the first significant digit and in exponent form otherwise. */
static void python_float_repr(double d, char *out, size_t out_len) {
    char sci[64];
    int prec;
    for (prec = 0; prec <= 16; prec++) {
        snprintf(sci, sizeof sci, "%.*e", prec, d);
        if (strtod(sci, NULL) == d) break;
    }
    /* sci is [-]d[.ddd]e[+-]xx: collect the digits and the exponent. */
    const char *p = sci;
    bool negative = *p == '-';
    if (negative) p++;
    char digits[32];
    int n = 0;
    while (*p && *p != 'e') { if (*p != '.') digits[n++] = *p; p++; }
    int exponent = atoi(p + 1);
    while (n > 1 && digits[n - 1] == '0') n--;
    digits[n] = '\0';
    int decpt = exponent + 1;           /* value = 0.digits * 10^decpt */
    char body[80];
    if (decpt > -4 && decpt <= 16) {
        char zeros[24] = "";
        if (decpt <= 0) {
            memset(zeros, '0', (size_t)-decpt);
            snprintf(body, sizeof body, "0.%s%s", zeros, digits);
        } else if (decpt >= n) {
            memset(zeros, '0', (size_t)(decpt - n));
            snprintf(body, sizeof body, "%s%s.0", digits, zeros);
        } else {
            snprintf(body, sizeof body, "%.*s.%s", decpt, digits, digits + decpt);
        }
    } else {
        if (n > 1) snprintf(body, sizeof body, "%c.%se%c%02d", digits[0], digits + 1, exponent < 0 ? '-' : '+', abs(exponent));
        else snprintf(body, sizeof body, "%ce%c%02d", digits[0], exponent < 0 ? '-' : '+', abs(exponent));
    }
    snprintf(out, out_len, "%s%s", negative ? "-" : "", body);
}

static int dump_number(ppc_buf *b, const ppc_json *v) {
    char tmp[96];
    if (v->is_integer) {
        snprintf(tmp, sizeof tmp, "%lld", v->integer);
        return ppc_buf_append(b, tmp, strlen(tmp));
    }
    double d = v->number;
    if (isnan(d)) return ppc_buf_append(b, "NaN", 3);
    if (isinf(d)) return d > 0 ? ppc_buf_append(b, "Infinity", 8) : ppc_buf_append(b, "-Infinity", 9);
    python_float_repr(d, tmp, sizeof tmp);
    return ppc_buf_append(b, tmp, strlen(tmp));
}

static int dump(ppc_buf *b, const ppc_json *v) {
    int rc;
    switch (v->type) {
    case PPC_JSON_NULL: return ppc_buf_append(b, "null", 4);
    case PPC_JSON_BOOL: return v->boolean ? ppc_buf_append(b, "true", 4) : ppc_buf_append(b, "false", 5);
    case PPC_JSON_NUMBER: return dump_number(b, v);
    case PPC_JSON_STRING: return dump_string(b, v->string);
    case PPC_JSON_ARRAY:
        if ((rc = ppc_buf_append(b, "[", 1)) != PPC_OK) return rc;
        for (size_t i = 0; i < v->count; i++) {
            if (i && (rc = ppc_buf_append(b, ", ", 2)) != PPC_OK) return rc;
            if ((rc = dump(b, v->items[i])) != PPC_OK) return rc;
        }
        return ppc_buf_append(b, "]", 1);
    case PPC_JSON_OBJECT:
        if ((rc = ppc_buf_append(b, "{", 1)) != PPC_OK) return rc;
        for (size_t i = 0; i < v->count; i++) {
            if (i && (rc = ppc_buf_append(b, ", ", 2)) != PPC_OK) return rc;
            if ((rc = dump_string(b, v->keys[i])) != PPC_OK) return rc;
            if ((rc = ppc_buf_append(b, ": ", 2)) != PPC_OK) return rc;
            if ((rc = dump(b, v->items[i])) != PPC_OK) return rc;
        }
        return ppc_buf_append(b, "}", 1);
    }
    return PPC_ERR_INVALID;
}

char *ppc_json_dump(const ppc_json *v) {
    if (v == NULL) return NULL;
    ppc_buf b = {0};
    if (dump(&b, v) != PPC_OK || ppc_buf_append(&b, "", 1) != PPC_OK) { ppc_buf_free(&b); return NULL; }
    return (char *)b.data;
}

ppc_json *ppc_json_clone(const ppc_json *v) {
    if (v == NULL) return NULL;
    ppc_json *out = NULL;
    switch (v->type) {
    case PPC_JSON_NULL: return ppc_json_new_null();
    case PPC_JSON_BOOL: return ppc_json_new_bool(v->boolean);
    case PPC_JSON_NUMBER: return v->is_integer ? ppc_json_new_integer(v->integer) : ppc_json_new_number(v->number);
    case PPC_JSON_STRING: return ppc_json_new_string(v->string);
    case PPC_JSON_ARRAY:
        out = ppc_json_new_array();
        for (size_t i = 0; out && i < v->count; i++)
            if (ppc_json_array_append(out, ppc_json_clone(v->items[i])) != PPC_OK) { ppc_json_free(out); return NULL; }
        return out;
    case PPC_JSON_OBJECT:
        out = ppc_json_new_object();
        for (size_t i = 0; out && i < v->count; i++)
            if (ppc_json_object_set(out, v->keys[i], ppc_json_clone(v->items[i])) != PPC_OK) { ppc_json_free(out); return NULL; }
        return out;
    }
    return NULL;
}
