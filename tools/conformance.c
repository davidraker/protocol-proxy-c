/* conformance: launch a proxy through the C manager and check it against PROTOCOL.md, the counterpart of the Python
 * protocol-proxy-conformance command and the Go port's:
 *
 *   conformance <manifest.toml | proxy name> [--echo METHOD] [--tls] [--manager-dials] [--option NAME=VALUE ...]
 *               [--timeout S] [--python PATH] [--json] [-v]
 *
 * Exit 0 when every check passes or is skipped, 1 on a failure, 2 on a usage or manifest error. */
#include "ppc/ppc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out) {
    fprintf(out, "usage: conformance <manifest.toml | proxy name> [--echo METHOD] [--tls] [--manager-dials]"
                 " [--option NAME=VALUE ...] [--timeout S] [--python PATH] [--json] [-v]\n");
}

int main(int argc, char **argv) {
    const char *target = NULL, *echo = NULL, *python = NULL;
    bool tls = false, manager_dials = false, as_json = false, verbose = false;
    double timeout = 20.0;
    ppc_option options[64];
    char *option_text[64];
    size_t n_options = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *value = NULL;
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) { usage(stdout); return 0; }
        if (strcmp(a, "--tls") == 0) { tls = true; continue; }
        if (strcmp(a, "--manager-dials") == 0) { manager_dials = true; continue; }
        if (strcmp(a, "--json") == 0) { as_json = true; continue; }
        if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) { verbose = true; continue; }
        if (strncmp(a, "--", 2) == 0) {
            const char *eq = strchr(a, '=');
            size_t name_len = eq ? (size_t)(eq - a) : strlen(a);
            if (eq) value = eq + 1;
            else if (i + 1 < argc) value = argv[++i];
            else { fprintf(stderr, "conformance: %s needs a value\n", a); usage(stderr); return 2; }
            if (strncmp(a, "--echo", name_len) == 0 && name_len == 6) echo = value;
            else if (strncmp(a, "--python", name_len) == 0 && name_len == 8) python = value;
            else if (strncmp(a, "--timeout", name_len) == 0 && name_len == 9) timeout = atof(value);
            else if (strncmp(a, "--option", name_len) == 0 && name_len == 8) {
                char *copy = strdup(value);
                char *sep = copy ? strchr(copy, '=') : NULL;
                if (sep == NULL || n_options == sizeof options / sizeof *options) {
                    fprintf(stderr, "conformance: --option needs NAME=VALUE, got \"%s\"\n", value);
                    free(copy);
                    return 2;
                }
                *sep = '\0';
                option_text[n_options] = copy;
                options[n_options].name = copy;
                options[n_options].value = sep + 1;
                n_options++;
            } else { fprintf(stderr, "conformance: unknown option %s\n", a); usage(stderr); return 2; }
            continue;
        }
        if (target) { usage(stderr); return 2; }
        target = a;
    }
    if (target == NULL) { usage(stderr); return 2; }
    ppc_log_init(verbose ? "DEBUG" : "CRITICAL", 0, "conformance");
    if (!verbose) ppc_log_set_level(PPC_LOG_CRITICAL + 50);         /* the manager's own log stays quiet */
    char err[1024];
    ppc_manifest *m;
    size_t len = strlen(target);
    if ((len > 5 && strcmp(target + len - 5, ".toml") == 0) || strchr(target, '/')) m = ppc_manifest_load(target, err, sizeof err);
    else m = ppc_manifest_find(target, err, sizeof err);
    if (m == NULL) { fprintf(stderr, "conformance: %s\n", err); return 2; }
    ppc_conformance_options opts;
    memset(&opts, 0, sizeof opts);
    opts.launch_options = options;
    opts.n_launch_options = n_options;
    opts.echo_method = echo;
    opts.tls = tls;
    opts.manager_dials = manager_dials;
    opts.timeout = timeout;
    opts.python = python;
    opts.records = verbose ? ppc_record_log : NULL;
    ppc_conformance_report *report = ppc_conformance_run(m, &opts);
    int code = 1;
    if (report) {
        char *text = as_json ? ppc_conformance_json(report) : ppc_conformance_text(report);
        if (text) { puts(text); free(text); }
        code = ppc_conformance_ok(report) ? 0 : 1;
        ppc_conformance_report_free(report);
    }
    ppc_manifest_free(m);
    for (size_t i = 0; i < n_options; i++) free(option_text[i]);
    return code;
}
