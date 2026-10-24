/* echo-proxy: a protocol-proxy that answers ECHO with its payload, built on the C library. Launched by a manager
 * with the standard command line of PROTOCOL.md section 1 (plus any protocol options, which it ignores).
 *
 *   echo-proxy --proxy-id <hex> --proxy-name <str> --manager-id <hex> [--manager-address <host>] ...
 *   echo-proxy --self-test [--vectors <test_vectors.json>]
 *   echo-proxy --version
 */
#include "ppc/ppc.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VERSION "0.1.0"

static int handle_echo(ppc_connector *c, const ppc_header *h, const uint8_t *payload, size_t len, uint8_t **reply,
                       size_t *reply_len, void *user) {
    (void)c; (void)h; (void)user;
    uint8_t *copy = malloc(len ? len : 1);
    if (copy == NULL) return PPC_ERR_NOMEM;
    if (len) memcpy(copy, payload, len);
    *reply = copy;
    *reply_len = len;
    return PPC_OK;
}

/* The vectors file: --vectors, $PROTOCOL_PROXY_VECTORS, or tests/test_vectors.json beside the binary's directory. */
static int find_vectors(const char *given, char *out, size_t out_len) {
    if (given) { snprintf(out, out_len, "%s", given); return access(out, R_OK); }
    const char *env = getenv("PROTOCOL_PROXY_VECTORS");
    if (env && *env) { snprintf(out, out_len, "%s", env); return access(out, R_OK); }
    char exe[PATH_MAX - 64];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n > 0) {
        exe[n] = '\0';
        char *slash = strrchr(exe, '/');
        if (slash) *slash = '\0';
        snprintf(out, out_len, "%s/../tests/test_vectors.json", exe);
        if (access(out, R_OK) == 0) return 0;
        snprintf(out, out_len, "%s/test_vectors.json", exe);
        if (access(out, R_OK) == 0) return 0;
    }
    snprintf(out, out_len, "tests/test_vectors.json");
    return access(out, R_OK);
}

static int self_test(int argc, char **argv) {
    const char *given = NULL;
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "--vectors") == 0 && i + 1 < argc) given = argv[++i];
    char path[PATH_MAX];
    if (find_vectors(given, path, sizeof path) != 0) {
        fprintf(stderr, "echo-proxy --self-test: cannot find test_vectors.json (tried %s); pass --vectors <path>\n", path);
        return 2;
    }
    int failures = ppc_selftest_vectors(path, stderr);
    if (failures != 0) return 1;
    /* The PING and SET_LOG_LEVEL shapes, without a manager. */
    ppc_proxy_options opts;
    memset(&opts, 0, sizeof opts);
    char *argv_fake[] = {"echo-proxy", "--proxy-id", "11111111222233334444555555555555", "--proxy-name", "self-test",
                         "--manager-id", "99999999888877776666555555555555", "--manager-dials", "true"};
    char err[256];
    if (ppc_proxy_options_parse(9, argv_fake, &opts, err, sizeof err) != PPC_OK) { fprintf(stderr, "options: %s\n", err); return 1; }
    ppc_proxy_secrets secrets;
    memset(&secrets, 0, sizeof secrets);
    ppc_proxy *p = ppc_proxy_new(&opts, &secrets, NULL, 0);
    int rc = 0;
    if (p == NULL) { fprintf(stderr, "ppc_proxy_new failed\n"); rc = 1; }
    else {
        char *health = ppc_proxy_health_json(p);
        ppc_json *v = health ? ppc_json_parse(health, strlen(health), err, sizeof err) : NULL;
        if (v == NULL || ppc_json_get(v, "uptime") == NULL || ppc_json_get(v, "remotes") == NULL
            || ppc_json_get(v, "busy") == NULL || ppc_json_get(v, "last_activity") == NULL) {
            fprintf(stderr, "PING reply shape wrong: %s\n", health ? health : "(null)");
            rc = 1;
        }
        ppc_json_free(v);
        free(health);
        ppc_proxy_free(p);
    }
    ppc_proxy_options_free(&opts);
    fprintf(stderr, "echo-proxy self test: %s\n", rc == 0 ? "ok" : "FAILED");
    return rc;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--self-test") == 0) return self_test(argc, argv);
        if (strcmp(argv[i], "--version") == 0) { printf("echo-proxy %s\n", VERSION); return 0; }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("usage: echo-proxy --proxy-id <hex> --proxy-name <str> --manager-id <hex> [--manager-address <host>]\n"
                   "       [--manager-port <int>] [--inbound-address <host>] [--inbound-port <int>] [--encrypt true|false]\n"
                   "       [--cipher auto|aes-256-gcm|chacha20-poly1305] [--ipc-tls true|false] [--manager-dials true|false]\n"
                   "       [--persistent true|false] [--socket-logging true|false] [--compress-threshold <int>]\n"
                   "       [--log-level <LEVEL>] [--<option> <value> ...]\n"
                   "       echo-proxy --self-test [--vectors <test_vectors.json>]\n"
                   "Tokens (and key, TLS material) are read from stdin as a ProtocolProxyManager writes them.\n");
            return 0;
        }
    }
    ppc_proxy_options opts;
    char err[256];
    if (ppc_proxy_options_parse(argc, argv, &opts, err, sizeof err) != PPC_OK) {
        fprintf(stderr, "echo-proxy: %s\n", err);
        ppc_proxy_options_free(&opts);
        return 2;
    }
    ppc_log_init(opts.log_level, -1, "echo-proxy");
    PPC_LOG_AT(PPC_LOG_INFO, "echo_proxy", "Launching echo-proxy %s as %s (manager %s:%d, encrypt=%s, tls=%s, manager_dials=%s, persistent=%s, %zu protocol option(s)).",
               VERSION, opts.proxy_name, opts.manager_address, opts.manager_port, opts.encrypt ? "true" : "false",
               opts.ipc_tls ? "true" : "false", opts.manager_dials ? "true" : "false", opts.persistent ? "true" : "false", opts.extra_count);
    for (size_t i = 0; i < opts.extra_count; i++)
        PPC_LOG_AT(PPC_LOG_INFO, "echo_proxy", "Ignoring protocol option --%s.", opts.extra_names[i]);
    ppc_proxy_secrets secrets;
    if (ppc_proxy_read_secrets(stdin, opts.encrypt, opts.ipc_tls, &secrets, err, sizeof err) != PPC_OK) {
        PPC_LOG_AT(PPC_LOG_ERROR, "echo_proxy", "Proxy Launch: %s", err);
        ppc_proxy_options_free(&opts);
        return 1;
    }
    ppc_proxy *proxy = ppc_proxy_new(&opts, &secrets, NULL, 0);
    if (proxy == NULL) {
        PPC_LOG_AT(PPC_LOG_ERROR, "echo_proxy", "Proxy Launch: proxy terminated: unable to create the proxy.");
        ppc_proxy_secrets_free(&secrets);
        ppc_proxy_options_free(&opts);
        return 1;
    }
    ppc_proxy_register_handler(proxy, "ECHO", handle_echo, NULL, true);
    int code = ppc_proxy_run(proxy);
    ppc_proxy_free(proxy);
    ppc_proxy_secrets_free(&secrets);
    ppc_proxy_options_free(&opts);
    return code;
}
