/* Proxy manifests (section 1a): proxy.toml parsed and validated as the Python reference does, process keys and
 * must_match conflicts, placeholder resolution, and discovery along the section 1a search path. TOML parsing is
 * tomlc99 (third_party/tomlc99, MIT); the tree is converted to ppc_json so one validator serves both. */
#include "internal.h"

#include <ctype.h>
#include <stdarg.h>
#include <dirent.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "toml.h"

#define MANIFEST_FILENAME "proxy.toml"
#define MANIFEST_SUBDIR "protocol-proxy/manifests"
#define ENV_MANIFEST_PATH "PROTOCOL_PROXY_MANIFESTS"
#define ENV_PREFIX "PROTOCOL_PROXY_PREFIX"

typedef struct {
    char *key;
    ppc_json *steps;        /* array of "lowercase" | "strip" | {"default": value} */
} normalize_rule;

struct ppc_manifest {
    char *name;
    char **command;
    size_t n_command;
    int header_version;
    char **keys;
    size_t n_keys;
    char **must_match;
    size_t n_must_match;
    normalize_rule *normalize;
    size_t n_normalize;
    char **env_names, **env_values;
    size_t n_env;
    char **self_test;
    size_t n_self_test;
    char *source;
    char *dir;
};

static void set_err(char *err, size_t err_len, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void set_err(char *err, size_t err_len, const char *fmt, ...) {
    if (err == NULL || err_len == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, err_len, fmt, ap);
    va_end(ap);
}

/* ---- TOML to JSON --------------------------------------------------------------------------------------------- */
static ppc_json *raw_to_json(toml_raw_t raw) {
    char *s = NULL;
    int b = 0;
    int64_t i = 0;
    double d = 0;
    if (toml_rtos(raw, &s) == 0) { ppc_json *v = ppc_json_new_string(s); free(s); return v; }
    if (toml_rtob(raw, &b) == 0) return ppc_json_new_bool(b != 0);
    if (toml_rtoi(raw, &i) == 0) return ppc_json_new_integer((long long)i);
    if (toml_rtod(raw, &d) == 0) return ppc_json_new_number(d);
    return ppc_json_new_string(raw);        /* a timestamp: kept as its text */
}

static ppc_json *table_to_json(const toml_table_t *tab);

static ppc_json *array_to_json(const toml_array_t *arr) {
    ppc_json *out = ppc_json_new_array();
    if (out == NULL) return NULL;
    int n = toml_array_nelem(arr);
    for (int i = 0; i < n; i++) {
        ppc_json *item = NULL;
        toml_raw_t raw = toml_raw_at(arr, i);
        const toml_table_t *tab;
        const toml_array_t *sub;
        if (raw) item = raw_to_json(raw);
        else if ((tab = toml_table_at(arr, i)) != NULL) item = table_to_json(tab);
        else if ((sub = toml_array_at(arr, i)) != NULL) item = array_to_json(sub);
        else item = ppc_json_new_null();
        if (ppc_json_array_append(out, item) != PPC_OK) { ppc_json_free(out); return NULL; }
    }
    return out;
}

static ppc_json *table_to_json(const toml_table_t *tab) {
    ppc_json *out = ppc_json_new_object();
    if (out == NULL) return NULL;
    for (int i = 0;; i++) {
        const char *key = toml_key_in(tab, i);
        if (key == NULL) break;
        ppc_json *value = NULL;
        toml_raw_t raw = toml_raw_in(tab, key);
        const toml_array_t *arr;
        const toml_table_t *sub;
        if (raw) value = raw_to_json(raw);
        else if ((arr = toml_array_in(tab, key)) != NULL) value = array_to_json(arr);
        else if ((sub = toml_table_in(tab, key)) != NULL) value = table_to_json(sub);
        else value = ppc_json_new_null();
        if (ppc_json_object_set(out, key, value) != PPC_OK) { ppc_json_free(out); return NULL; }
    }
    return out;
}

/* ---- validation ----------------------------------------------------------------------------------------------- */
static const char *where(const char *source) { return source ? source : "manifest"; }

static bool only(const ppc_json *table, const char *const *allowed, size_t n_allowed, const char *w, char *err, size_t err_len) {
    char unknown[256] = "";
    for (size_t i = 0; i < table->count; i++) {
        bool ok = false;
        for (size_t j = 0; j < n_allowed && !ok; j++) if (strcmp(table->keys[i], allowed[j]) == 0) ok = true;
        if (!ok) {
            size_t len = strlen(unknown);
            snprintf(unknown + len, sizeof unknown - len, "%s%s", len ? ", " : "", table->keys[i]);
        }
    }
    if (unknown[0]) {
        char list[256] = "";
        for (size_t j = 0; j < n_allowed; j++) { size_t len = strlen(list); snprintf(list + len, sizeof list - len, "%s%s", len ? ", " : "", allowed[j]); }
        set_err(err, err_len, "%s: unknown keys [%s]; allowed: [%s]", w, unknown, list);
        return false;
    }
    return true;
}

/* The [key] table of data: NULL with an error when it is required and absent or not a table; an empty object
 * (owned by the caller, *created set) when optional and absent. */
static const ppc_json *table(const ppc_json *data, const char *key, const char *w, bool required, ppc_json **created,
                             char *err, size_t err_len) {
    *created = NULL;
    const ppc_json *v = ppc_json_get(data, key);
    if (v == NULL || v->type == PPC_JSON_NULL) {
        if (required) { set_err(err, err_len, "%s: the [%s] table is required", w, key); return NULL; }
        *created = ppc_json_new_object();
        return *created;
    }
    if (v->type != PPC_JSON_OBJECT) { set_err(err, err_len, "%s: [%s] must be a table", w, key); return NULL; }
    return v;
}

static bool valid_placeholder(const char *name, size_t len) {
    return (len == 6 && strncmp(name, "python", 6) == 0) || (len == 12 && strncmp(name, "manifest_dir", 12) == 0);
}

/* Every {name} in text must be a known placeholder; the offending one lands in err. */
static bool placeholders_ok(const char *text, const char *w, char *err, size_t err_len) {
    for (const char *p = strchr(text, '{'); p; p = strchr(p + 1, '{')) {
        const char *q = p + 1;
        while (*q && (islower((unsigned char)*q) || *q == '_')) q++;
        if (*q == '}' && !valid_placeholder(p + 1, (size_t)(q - p - 1))) {
            set_err(err, err_len, "%s: unknown placeholder {%.*s}; allowed: [manifest_dir python]", w, (int)(q - p - 1), p + 1);
            return false;
        }
    }
    return true;
}

static char **command_list(const ppc_json *value, const char *w, size_t *count, char *err, size_t err_len) {
    if (value == NULL || value->type != PPC_JSON_ARRAY || value->count == 0) {
        set_err(err, err_len, "%s: must be a non-empty list of strings", w);
        return NULL;
    }
    char **out = calloc(value->count + 1, sizeof *out);
    if (out == NULL) return NULL;
    for (size_t i = 0; i < value->count; i++) {
        const ppc_json *item = value->items[i];
        if (item->type != PPC_JSON_STRING || item->string[0] == '\0') {
            set_err(err, err_len, "%s: must be a non-empty list of strings", w);
            ppc_strings_free(out, i);
            return NULL;
        }
        if (!placeholders_ok(item->string, w, err, err_len)) { ppc_strings_free(out, i); return NULL; }
        out[i] = ppc_strdup(item->string);
        if (out[i] == NULL) { ppc_strings_free(out, i); return NULL; }
    }
    *count = value->count;
    return out;
}

static char **names(const ppc_json *value, const char *w, size_t *count, bool *ok, char *err, size_t err_len) {
    *count = 0;
    *ok = true;
    if (value == NULL || value->type == PPC_JSON_NULL) return NULL;
    if (value->type != PPC_JSON_ARRAY) { set_err(err, err_len, "%s: must be a list of option names", w); *ok = false; return NULL; }
    char **out = calloc(value->count + 1, sizeof *out);
    if (out == NULL) { *ok = false; return NULL; }
    for (size_t i = 0; i < value->count; i++) {
        if (value->items[i]->type != PPC_JSON_STRING || value->items[i]->string[0] == '\0') {
            set_err(err, err_len, "%s: must be a list of option names", w);
            ppc_strings_free(out, i);
            *ok = false;
            return NULL;
        }
        out[i] = ppc_strdup(value->items[i]->string);
    }
    *count = value->count;
    return out;
}

static bool known_name(const ppc_manifest *m, const char *key) {
    for (size_t i = 0; i < m->n_keys; i++) if (strcmp(m->keys[i], key) == 0) return true;
    for (size_t i = 0; i < m->n_must_match; i++) if (strcmp(m->must_match[i], key) == 0) return true;
    return false;
}

static bool parse_identity(ppc_manifest *m, const ppc_json *t, const char *w, char *err, size_t err_len) {
    static const char *const allowed[] = {"keys", "must_match", "normalize"};
    if (!only(t, allowed, 3, w, err, err_len)) return false;
    bool ok;
    char sub[640];
    snprintf(sub, sizeof sub, "%s keys", w);
    m->keys = names(ppc_json_get(t, "keys"), sub, &m->n_keys, &ok, err, err_len);
    if (!ok) return false;
    snprintf(sub, sizeof sub, "%s must_match", w);
    m->must_match = names(ppc_json_get(t, "must_match"), sub, &m->n_must_match, &ok, err, err_len);
    if (!ok) return false;
    const ppc_json *normalize = ppc_json_get(t, "normalize");
    if (normalize == NULL || normalize->type != PPC_JSON_OBJECT) return true;
    m->normalize = calloc(normalize->count + 1, sizeof *m->normalize);
    if (m->normalize == NULL) return false;
    for (size_t i = 0; i < normalize->count; i++) {
        const char *key = normalize->keys[i];
        const ppc_json *steps = normalize->items[i];
        if (!known_name(m, key)) { set_err(err, err_len, "%s.normalize: \"%s\" is not in keys or must_match", w, key); return false; }
        if (steps->type != PPC_JSON_ARRAY) { set_err(err, err_len, "%s.normalize: %s must be a list of steps", w, key); return false; }
        for (size_t j = 0; j < steps->count; j++) {
            const ppc_json *step = steps->items[j];
            if (step->type == PPC_JSON_STRING) {
                if (strcmp(step->string, "lowercase") != 0 && strcmp(step->string, "strip") != 0) {
                    set_err(err, err_len, "%s.normalize: unknown normaliser \"%s\" for %s; allowed: [lowercase strip] or { default = <value> }", w, step->string, key);
                    return false;
                }
            } else if (step->type == PPC_JSON_OBJECT) {
                if (step->count != 1 || strcmp(step->keys[0], "default") != 0) {
                    char *text = ppc_json_dump(step);
                    set_err(err, err_len, "%s.normalize: a step is a normaliser name or { default = <value> }, got %s", w, text ? text : "?");
                    free(text);
                    return false;
                }
            } else {
                char *text = ppc_json_dump(step);
                set_err(err, err_len, "%s.normalize: a step is a normaliser name or { default = <value> }, got %s", w, text ? text : "?");
                free(text);
                return false;
            }
        }
        m->normalize[m->n_normalize].key = ppc_strdup(key);
        m->normalize[m->n_normalize].steps = ppc_json_clone(steps);
        if (m->normalize[m->n_normalize].key == NULL || m->normalize[m->n_normalize].steps == NULL) return false;
        m->n_normalize++;
    }
    return true;
}

static bool valid_name(const char *name) {
    if (name == NULL || *name == '\0') return false;
    for (const char *p = name; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '.' && *p != '-') return false;
    return true;
}

static ppc_manifest *from_json(const ppc_json *data, const char *source, char *err, size_t err_len) {
    const char *w = where(source);
    char sub[512];
    static const char *const top[] = {"proxy", "identity", "environment", "self_test"};
    static const char *const proxy_keys[] = {"name", "command", "header_version"};
    static const char *const self_test_keys[] = {"command"};
    if (data->type != PPC_JSON_OBJECT) { set_err(err, err_len, "%s: not a table", w); return NULL; }
    if (!only(data, top, 4, w, err, err_len)) return NULL;
    ppc_manifest *m = calloc(1, sizeof *m);
    if (m == NULL) return NULL;
    m->header_version = 2;
    ppc_json *created = NULL;
    const ppc_json *proxy = table(data, "proxy", w, true, &created, err, err_len);
    if (proxy == NULL) goto fail;
    snprintf(sub, sizeof sub, "%s [proxy]", w);
    if (!only(proxy, proxy_keys, 3, sub, err, err_len)) goto fail;
    const ppc_json *name = ppc_json_get(proxy, "name");
    if (name == NULL || name->type != PPC_JSON_STRING || !valid_name(name->string)) {
        char *text = name ? ppc_json_dump(name) : NULL;
        set_err(err, err_len, "%s [proxy]: name must be a short identifier, got %s", w, text ? text : "None");
        free(text);
        goto fail;
    }
    m->name = ppc_strdup(name->string);
    snprintf(sub, sizeof sub, "%s [proxy] command", w);
    m->command = command_list(ppc_json_get(proxy, "command"), sub, &m->n_command, err, err_len);
    if (m->command == NULL) goto fail;
    const ppc_json *hv = ppc_json_get(proxy, "header_version");
    if (hv) {
        if (hv->type != PPC_JSON_NUMBER || !hv->is_integer || (hv->integer != 1 && hv->integer != 2)) {
            char *text = ppc_json_dump(hv);
            set_err(err, err_len, "%s [proxy]: header_version must be 1 or 2, got %s", w, text ? text : "?");
            free(text);
            goto fail;
        }
        m->header_version = (int)hv->integer;
    }
    const ppc_json *identity = table(data, "identity", w, false, &created, err, err_len);
    if (identity == NULL) goto fail;
    snprintf(sub, sizeof sub, "%s [identity]", w);
    bool ok = parse_identity(m, identity, sub, err, err_len);
    ppc_json_free(created);
    created = NULL;
    if (!ok) goto fail;
    const ppc_json *environment = table(data, "environment", w, false, &created, err, err_len);
    if (environment == NULL) goto fail;
    m->env_names = calloc(environment->count + 1, sizeof *m->env_names);
    m->env_values = calloc(environment->count + 1, sizeof *m->env_values);
    if (m->env_names == NULL || m->env_values == NULL) goto fail;
    for (size_t i = 0; i < environment->count; i++) {
        if (environment->items[i]->type != PPC_JSON_STRING) { set_err(err, err_len, "%s [environment]: values must be strings", w); goto fail; }
        snprintf(sub, sizeof sub, "%s [environment] %s", w, environment->keys[i]);
        if (!placeholders_ok(environment->items[i]->string, sub, err, err_len)) goto fail;
        m->env_names[i] = ppc_strdup(environment->keys[i]);
        m->env_values[i] = ppc_strdup(environment->items[i]->string);
        m->n_env++;
    }
    ppc_json_free(created);
    created = NULL;
    const ppc_json *self_test = table(data, "self_test", w, false, &created, err, err_len);
    if (self_test == NULL) goto fail;
    if (self_test->count) {
        snprintf(sub, sizeof sub, "%s [self_test]", w);
        if (!only(self_test, self_test_keys, 1, sub, err, err_len)) goto fail;
        snprintf(sub, sizeof sub, "%s [self_test] command", w);
        m->self_test = command_list(ppc_json_get(self_test, "command"), sub, &m->n_self_test, err, err_len);
        if (m->self_test == NULL) goto fail;
    }
    ppc_json_free(created);
    created = NULL;
    if (source) {
        m->source = ppc_strdup(source);
        m->dir = ppc_strdup(source);
        if (m->source == NULL || m->dir == NULL) goto fail;
        char *slash = strrchr(m->dir, '/');
        if (slash == m->dir) m->dir[1] = '\0';
        else if (slash) *slash = '\0';
        else { free(m->dir); m->dir = ppc_strdup("."); }
    } else {
        m->dir = ppc_strdup("");
    }
    return m;
fail:
    ppc_json_free(created);
    ppc_manifest_free(m);
    return NULL;
}

ppc_manifest *ppc_manifest_parse(const char *text, const char *source, char *err, size_t err_len) {
    if (text == NULL) return NULL;
    if (err && err_len) err[0] = '\0';
    char *copy = ppc_strdup(text);          /* tomlc99 wants a writable NUL-terminated buffer */
    if (copy == NULL) return NULL;
    char toml_err[200];
    toml_table_t *tab = toml_parse(copy, toml_err, sizeof toml_err);
    free(copy);
    if (tab == NULL) { set_err(err, err_len, "%s: not valid TOML: %s", where(source), toml_err); return NULL; }
    ppc_json *data = table_to_json(tab);
    toml_free(tab);
    if (data == NULL) return NULL;
    ppc_manifest *m = from_json(data, source, err, err_len);
    ppc_json_free(data);
    return m;
}

ppc_manifest *ppc_manifest_load(const char *path, char *err, size_t err_len) {
    if (path == NULL) return NULL;
    FILE *f = fopen(path, "rb");
    if (f == NULL) { set_err(err, err_len, "%s: %s", path, strerror(errno)); return NULL; }
    ppc_buf buf = {0};
    char chunk[4096];
    size_t n;
    while ((n = fread(chunk, 1, sizeof chunk, f)) > 0) ppc_buf_append(&buf, chunk, n);
    fclose(f);
    ppc_buf_append(&buf, "", 1);
    char abs[PATH_MAX];
    const char *source = realpath(path, abs) ? abs : path;
    ppc_manifest *m = buf.data ? ppc_manifest_parse((const char *)buf.data, source, err, err_len) : NULL;
    ppc_buf_free(&buf);
    return m;
}

void ppc_manifest_free(ppc_manifest *m) {
    if (m == NULL) return;
    free(m->name);
    ppc_strings_free(m->command, m->n_command);
    ppc_strings_free(m->keys, m->n_keys);
    ppc_strings_free(m->must_match, m->n_must_match);
    for (size_t i = 0; i < m->n_normalize; i++) { free(m->normalize[i].key); ppc_json_free(m->normalize[i].steps); }
    free(m->normalize);
    ppc_strings_free(m->env_names, m->n_env);
    ppc_strings_free(m->env_values, m->n_env);
    ppc_strings_free(m->self_test, m->n_self_test);
    free(m->source);
    free(m->dir);
    free(m);
}

const char *ppc_manifest_name(const ppc_manifest *m) { return m->name; }
const char *ppc_manifest_source(const ppc_manifest *m) { return m->source; }
const char *ppc_manifest_dir(const ppc_manifest *m) { return m->dir; }
int ppc_manifest_header_version(const ppc_manifest *m) { return m->header_version; }

size_t ppc_manifest_environment(const ppc_manifest *m, const char *const **names_out, const char *const **values) {
    if (names_out) *names_out = (const char *const *)m->env_names;
    if (values) *values = (const char *const *)m->env_values;
    return m->n_env;
}

size_t ppc_manifest_command(const ppc_manifest *m, const char *const **argv) {
    if (argv) *argv = (const char *const *)m->command;
    return m->n_command;
}

size_t ppc_manifest_must_match(const ppc_manifest *m, const char *const **names_out) {
    if (names_out) *names_out = (const char *const *)m->must_match;
    return m->n_must_match;
}

/* ---- placeholders and commands -------------------------------------------------------------------------------- */
static char *resolve(const ppc_manifest *m, const char *part, const char *python) {
    ppc_buf b = {0};
    for (const char *p = part; *p;) {
        if (*p == '{') {
            const char *q = p + 1;
            while (*q && (islower((unsigned char)*q) || *q == '_')) q++;
            if (*q == '}') {
                size_t len = (size_t)(q - p - 1);
                if (len == 6 && strncmp(p + 1, "python", 6) == 0) { ppc_buf_append(&b, python, strlen(python)); p = q + 1; continue; }
                if (len == 12 && strncmp(p + 1, "manifest_dir", 12) == 0) { ppc_buf_append(&b, m->dir, strlen(m->dir)); p = q + 1; continue; }
            }
        }
        ppc_buf_append(&b, p, 1);
        p++;
    }
    ppc_buf_append(&b, "", 1);
    return (char *)b.data;
}

char **ppc_manifest_launch_command(const ppc_manifest *m, const char *python, const char *const *standard,
                                   size_t n_standard, size_t *argc) {
    if (python == NULL) python = "python3";
    char **argv = calloc(m->n_command + n_standard + 1, sizeof *argv);
    if (argv == NULL) return NULL;
    size_t n = 0;
    for (size_t i = 0; i < m->n_command; i++) {
        argv[n] = resolve(m, m->command[i], python);
        if (argv[n] == NULL) { ppc_strings_free(argv, n); return NULL; }
        n++;
    }
    for (size_t i = 0; i < n_standard; i++) {
        argv[n] = ppc_strdup(standard[i]);
        if (argv[n] == NULL) { ppc_strings_free(argv, n); return NULL; }
        n++;
    }
    if (argc) *argc = n;
    return argv;
}

char **ppc_manifest_resolved_environment(const ppc_manifest *m, const char *python, size_t *count) {
    if (python == NULL) python = "python3";
    char **values = calloc(m->n_env + 1, sizeof *values);
    if (values == NULL) return NULL;
    for (size_t i = 0; i < m->n_env; i++) {
        values[i] = resolve(m, m->env_values[i], python);
        if (values[i] == NULL) { ppc_strings_free(values, i); return NULL; }
    }
    if (count) *count = m->n_env;
    return values;
}

char **ppc_manifest_self_test_command(const ppc_manifest *m, const char *python, size_t *argc) {
    if (m->self_test == NULL) { if (argc) *argc = 0; return NULL; }
    if (python == NULL) python = "python3";
    char **argv = calloc(m->n_self_test + 1, sizeof *argv);
    if (argv == NULL) return NULL;
    for (size_t i = 0; i < m->n_self_test; i++) {
        argv[i] = resolve(m, m->self_test[i], python);
        if (argv[i] == NULL) { ppc_strings_free(argv, i); return NULL; }
    }
    if (argc) *argc = m->n_self_test;
    return argv;
}

/* ---- identity -------------------------------------------------------------------------------------------------- */
const char *ppc_options_get(const ppc_option *options, size_t n, const char *name) {
    for (size_t i = 0; i < n; i++) if (options[i].name && strcmp(options[i].name, name) == 0) return options[i].value;
    return NULL;
}

bool ppc_option_bool(const char *value, bool dflt) {
    if (value == NULL) return dflt;
    char lowered[16];
    size_t n = strlen(value);
    while (n && isspace((unsigned char)value[n - 1])) n--;
    while (n && isspace((unsigned char)*value)) { value++; n--; }
    if (n >= sizeof lowered) return dflt;
    for (size_t i = 0; i < n; i++) lowered[i] = (char)tolower((unsigned char)value[i]);
    lowered[n] = '\0';
    static const char *const yes[] = {"1", "true", "t", "yes", "y", "on"};
    static const char *const no[] = {"0", "false", "f", "no", "n", "off", ""};
    for (size_t i = 0; i < sizeof yes / sizeof *yes; i++) if (strcmp(lowered, yes[i]) == 0) return true;
    for (size_t i = 0; i < sizeof no / sizeof *no; i++) if (strcmp(lowered, no[i]) == 0) return false;
    return dflt;
}

/* value of option key after the manifest's normalisers (NULL value: None, which takes the default). Returns a new
 * JSON value: a string, the default's value, or null. */
static ppc_json *normalized(const ppc_manifest *m, const char *key, const char *value) {
    ppc_json *current = value ? ppc_json_new_string(value) : ppc_json_new_null();
    const normalize_rule *rule = NULL;
    for (size_t i = 0; i < m->n_normalize; i++) if (strcmp(m->normalize[i].key, key) == 0) rule = &m->normalize[i];
    if (rule == NULL || current == NULL) return current;
    for (size_t j = 0; j < rule->steps->count; j++) {
        const ppc_json *step = rule->steps->items[j];
        if (step->type == PPC_JSON_OBJECT) {
            if (current->type == PPC_JSON_NULL) { ppc_json_free(current); current = ppc_json_clone(ppc_json_get(step, "default")); if (current == NULL) return NULL; }
            continue;
        }
        if (current->type != PPC_JSON_STRING) continue;
        char *s = current->string;
        if (strcmp(step->string, "lowercase") == 0) {
            for (char *p = s; *p; p++) *p = (char)tolower((unsigned char)*p);
        } else if (strcmp(step->string, "strip") == 0) {
            size_t n = strlen(s);
            while (n && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
            size_t lead = 0;
            while (s[lead] && isspace((unsigned char)s[lead])) lead++;
            if (lead) memmove(s, s + lead, n - lead + 1);
        }
    }
    return current;
}

ppc_json *ppc_manifest_process_key(const ppc_manifest *m, const char *const *unique_remote_id, size_t id_count,
                                   const ppc_option *options, size_t n_options) {
    ppc_json *key = ppc_json_new_array();
    if (key == NULL) return NULL;
    if (m->n_keys == 0) {
        for (size_t i = 0; i < id_count; i++)
            if (ppc_json_array_append(key, ppc_json_new_string(unique_remote_id[i])) != PPC_OK) { ppc_json_free(key); return NULL; }
        return key;
    }
    if (ppc_json_array_append(key, ppc_json_new_string(m->name)) != PPC_OK) { ppc_json_free(key); return NULL; }
    for (size_t i = 0; i < m->n_keys; i++) {
        ppc_json *v = normalized(m, m->keys[i], ppc_options_get(options, n_options, m->keys[i]));
        if (ppc_json_array_append(key, v) != PPC_OK) { ppc_json_free(key); return NULL; }
    }
    return key;
}

char *ppc_manifest_conflicts(const ppc_manifest *m, const ppc_option *first, size_t n_first,
                             const ppc_option *options, size_t n_options) {
    ppc_buf b = {0};
    for (size_t i = 0; i < m->n_must_match; i++) {
        const char *k = m->must_match[i];
        ppc_json *a = normalized(m, k, ppc_options_get(first, n_first, k));
        ppc_json *c = normalized(m, k, ppc_options_get(options, n_options, k));
        char *da = ppc_json_dump(a), *dc = ppc_json_dump(c);
        bool differ = da == NULL || dc == NULL || strcmp(da, dc) != 0;
        free(da); free(dc);
        ppc_json_free(a); ppc_json_free(c);
        if (differ) {
            if (b.len) ppc_buf_append(&b, ", ", 2);
            ppc_buf_append(&b, k, strlen(k));
        }
    }
    if (b.len == 0) return NULL;
    ppc_buf_append(&b, "", 1);
    return (char *)b.data;
}

static void py_repr(ppc_buf *b, const ppc_json *v) {
    char num[64];
    switch (v->type) {
    case PPC_JSON_NULL: ppc_buf_append(b, "None", 4); break;
    case PPC_JSON_BOOL: if (v->boolean) ppc_buf_append(b, "True", 4); else ppc_buf_append(b, "False", 5); break;
    case PPC_JSON_NUMBER:
        if (v->is_integer) snprintf(num, sizeof num, "%lld", v->integer);
        else if (v->number == (double)(long long)v->number) snprintf(num, sizeof num, "%lld", (long long)v->number);
        else snprintf(num, sizeof num, "%.17g", v->number);
        ppc_buf_append(b, num, strlen(num));
        break;
    case PPC_JSON_STRING: {
        bool single = strchr(v->string, '\'') != NULL, dbl = strchr(v->string, '"') != NULL;
        char quote = single && !dbl ? '"' : '\'';
        ppc_buf_append(b, &quote, 1);
        for (const char *p = v->string; *p; p++) {
            if (*p == '\\') ppc_buf_append(b, "\\\\", 2);
            else if (*p == quote) { ppc_buf_append(b, "\\", 1); ppc_buf_append(b, p, 1); }
            else if (*p == '\n') ppc_buf_append(b, "\\n", 2);
            else ppc_buf_append(b, p, 1);
        }
        ppc_buf_append(b, &quote, 1);
        break;
    }
    case PPC_JSON_ARRAY: {
        ppc_buf_append(b, "(", 1);
        for (size_t i = 0; i < v->count; i++) { if (i) ppc_buf_append(b, ", ", 2); py_repr(b, v->items[i]); }
        if (v->count == 1) ppc_buf_append(b, ",", 1);
        ppc_buf_append(b, ")", 1);
        break;
    }
    case PPC_JSON_OBJECT: {
        char *text = ppc_json_dump(v);
        if (text) { ppc_buf_append(b, text, strlen(text)); free(text); }
        break;
    }
    }
}

char *ppc_py_tuple(const ppc_json *key) {
    ppc_buf b = {0};
    if (key && key->type == PPC_JSON_ARRAY) py_repr(&b, key);
    else {
        ppc_buf_append(&b, "(", 1);
        if (key) { py_repr(&b, key); ppc_buf_append(&b, ",", 1); }
        ppc_buf_append(&b, ")", 1);
    }
    ppc_buf_append(&b, "", 1);
    return (char *)b.data;
}

/* ---- discovery ------------------------------------------------------------------------------------------------ */
static char *home_dir(void) {
    const char *home = getenv("HOME");
    if (home && *home) return ppc_strdup(home);
    struct passwd *pw = getpwuid(getuid());
    return pw && pw->pw_dir ? ppc_strdup(pw->pw_dir) : NULL;
}

static char *expand_user(const char *p) {
    if (p[0] == '~' && (p[1] == '\0' || p[1] == '/')) {
        char *home = home_dir();
        if (home) {
            size_t n = strlen(home) + strlen(p);
            char *out = malloc(n + 1);
            if (out) snprintf(out, n + 1, "%s%s", home, p + 1);
            free(home);
            return out;
        }
    }
    return ppc_strdup(p);
}

static char *join_path(const char *a, const char *b) {
    size_t n = strlen(a) + 1 + strlen(b);
    char *out = malloc(n + 1);
    if (out) snprintf(out, n + 1, "%s%s%s", a, a[strlen(a) - 1] == '/' ? "" : "/", b);
    return out;
}

typedef struct { char **items; size_t n; } string_list;

static void push_unique(string_list *l, char *s) {
    if (s == NULL) return;
    for (size_t i = 0; i < l->n; i++) if (strcmp(l->items[i], s) == 0) { free(s); return; }
    char **items = realloc(l->items, (l->n + 1) * sizeof *items);
    if (items == NULL) { free(s); return; }
    l->items = items;
    l->items[l->n++] = s;
}

static void push_split(string_list *l, const char *value, bool expand) {
    if (value == NULL) return;
    while (*value) {
        const char *end = strchr(value, ':');
        size_t len = end ? (size_t)(end - value) : strlen(value);
        if (len) {
            char *part = malloc(len + 1);
            if (part) {
                memcpy(part, value, len);
                part[len] = '\0';
                char *dir = expand ? expand_user(part) : join_path(part, MANIFEST_SUBDIR);
                if (expand) { free(part); push_unique(l, dir); }
                else { free(part); push_unique(l, dir); }
            }
        }
        if (end == NULL) break;
        value = end + 1;
    }
}

/* <prefix>/share/protocol-proxy/manifests: PROTOCOL_PROXY_PREFIX, else the directory above the executable's. */
static char *prefix_directory(void) {
    const char *env = getenv(ENV_PREFIX);
    char prefix[PATH_MAX];
    if (env && *env) snprintf(prefix, sizeof prefix, "%s", env);
    else {
        ssize_t n = readlink("/proc/self/exe", prefix, sizeof prefix - 1);
        if (n <= 0) return NULL;
        prefix[n] = '\0';
        char *slash = strrchr(prefix, '/');
        if (slash) *slash = '\0';
        slash = strrchr(prefix, '/');
        if (slash) *slash = '\0';
        if (prefix[0] == '\0') snprintf(prefix, sizeof prefix, "/");
    }
    char *share = join_path(prefix, "share");
    if (share == NULL) return NULL;
    char *dir = join_path(share, MANIFEST_SUBDIR);
    free(share);
    return dir;
}

char **ppc_manifest_search_path(size_t *count) {
    string_list l = {0};
    push_split(&l, getenv(ENV_MANIFEST_PATH), true);
    const char *config_home = getenv("XDG_CONFIG_HOME");
    if (config_home && *config_home) push_unique(&l, join_path(config_home, MANIFEST_SUBDIR));
    else {
        char *home = home_dir();
        if (home) { char *cfg = join_path(home, ".config"); if (cfg) push_unique(&l, join_path(cfg, MANIFEST_SUBDIR)); free(cfg); free(home); }
    }
    push_unique(&l, prefix_directory());
    const char *config_dirs = getenv("XDG_CONFIG_DIRS");
    push_split(&l, config_dirs && *config_dirs ? config_dirs : "/etc", false);
    const char *data_dirs = getenv("XDG_DATA_DIRS");
    push_split(&l, data_dirs && *data_dirs ? data_dirs : "/usr/local/share:/usr/share", false);
    if (count) *count = l.n;
    return l.items;
}

static bool is_file(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

char *ppc_manifest_locate(const char *name, char *err, size_t err_len) {
    size_t n = 0;
    char **dirs = ppc_manifest_search_path(&n);
    ppc_buf looked = {0};
    char *found = NULL;
    for (size_t i = 0; i < n && found == NULL; i++) {
        char file[PATH_MAX];
        snprintf(file, sizeof file, "%s.toml", name);
        char *a = join_path(dirs[i], file);
        snprintf(file, sizeof file, "%s/%s", name, MANIFEST_FILENAME);
        char *b = join_path(dirs[i], file);
        const char *candidates[2] = {a, b};
        for (int k = 0; k < 2 && found == NULL; k++) {
            if (candidates[k] == NULL) continue;
            if (looked.len) ppc_buf_append(&looked, ", ", 2);
            ppc_buf_append(&looked, candidates[k], strlen(candidates[k]));
            if (is_file(candidates[k])) found = ppc_strdup(candidates[k]);
        }
        free(a);
        free(b);
    }
    ppc_strings_free(dirs, n);
    if (found == NULL) {
        ppc_buf_append(&looked, "", 1);
        set_err(err, err_len, "no manifest for proxy \"%s\"; looked at: %s", name, looked.data ? (char *)looked.data : "");
    }
    ppc_buf_free(&looked);
    return found;
}

ppc_manifest *ppc_manifest_find(const char *name, char *err, size_t err_len) {
    char *path = ppc_manifest_locate(name, err, err_len);
    if (path == NULL) return NULL;
    ppc_manifest *m = ppc_manifest_load(path, err, err_len);
    free(path);
    return m;
}
