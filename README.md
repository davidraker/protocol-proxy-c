# protocol-proxy-c

A C port of the protocol-proxy package (the contract in the Python repository's `PROTOCOL.md`): the IPC library, the
proxy side, a `ProtocolProxyManager` that launches and hosts proxies written in any language, the manifest reader,
and two executables built on them: `echo-proxy`, a proxy that answers `PING`, `SET_LOG_LEVEL` and `ECHO`, and
`conformance`, the harness that checks any proxy against the contract through the C manager. A manager in any
language launches `echo-proxy` through the `proxy.toml` manifest; the C manager launches any proxy the same way.

What the library implements:

- Frames with version 1 and 2 headers (big-endian, byte-exact against `tests/test_vectors.json`); request ids cycle
  from 1 and fit the version's field.
- TCP listener and dialer (`AF_INET`), per-message and persistent connections in both directions, the keep-alive
  bit, adoption of an authenticated keep-alive connection, the 256 KiB large-frame rule, TCP keepalive.
- Authentication of every frame by sender id and token; dispatch by `(method, remote_id)` then `method`;
  `RESPONSE` matching by request id; the JSON error reply for unknown methods and handlers that give no response.
- zlib compression behind bit 1, only toward peers that advertised `compress` and only above the threshold
  (default 4096 bytes).
- AEAD encryption behind bit 2: ChaCha20-Poly1305, or AES-256-GCM behind bit 4, 12-byte random nonce, the whole
  header as associated data, key from stdin, mode fixed per peer (clear text from an encrypting peer and vice versa
  are refused and the connection is dropped).
- TLS 1.3 toward the manager (`--ipc-tls true`) with the material the manager writes to stdin; both certificates
  must chain to the manager's CA and a frame is accepted only if its sender id matches the certificate's common name.
- Registration (`REGISTER_PEER`) with two attempts, 5 s timeout, 20 s between attempts; manager-initiated
  registration with `--manager-dials true`.
- `PING` and `SET_LOG_LEVEL`; JSON log records on stderr with Python `LogRecord` attribute names when launched by a
  manager (readable text otherwise).
- `LOG` batches over the socket once registered, when launched by a manager with stderr a pipe and
  `--socket-logging true` (the default): records go through a bounded queue (2000 records, 50 per second with a burst
  of 200, drops counted in the batch), flushed every 0.2 s or at 64 records as a low-priority frame that never delays
  a request or reply on a persistent connection; at exit the queue is drained to stderr. `log` is advertised only when
  this applies, so a proxy run by hand logs readable text and advertises nothing it does not do.
- Parent-PID watch every second and SIGTERM handling, exit code 0 on a clean stop, a 15 s hard-exit guard.

## Layout

```
include/ppc/ppc.h    public API (headers, JSON, codecs, logging, connector, proxy, self test)
src/headers.c        header pack/unpack
src/json.c           JSON parser and writer (Python json.dumps formatting)
src/codec.c          zlib, ChaCha20-Poly1305 and AES-256-GCM (OpenSSL EVP), cipher selection
src/log.c            log records (JSON lines or text) on stderr, the bounded rate-limited LOG queue
src/tls.c            TLS material parsing and TLS 1.3 sessions over non-blocking sockets
src/connector.c      the IPC connector: listener, dialer, connections, authentication, dispatch, sending
src/proxy.c          the proxy process: command line, stdin handshake, registration, PING/SET_LOG_LEVEL, LOG batches, watchdog
src/selftest.c       checks every vector in tests/test_vectors.json
src/util.c           UUIDs, hex, buffers, timestamps
src/manifest.c       proxy.toml (section 1a): validation, process keys, must_match, placeholders, discovery
src/records.c        a launched proxy's log records: JSON lines, plain lines, <N> prefixes, LOG batches
src/authority.c      the in-memory certificate authority (EC P-256 CA, leaf certificates, the TLS material line)
src/manager.c        the manager: launch, stdin handshake, pipe readers, registration, heartbeat, LOG, stop, relaunch
src/conformance.c    the 26-check harness on the C manager
tools/echo-proxy.c   the proxy executable (ECHO handler, --self-test)
tools/conformance.c  the harness executable
third_party/tomlc99  the TOML parser (CK Tan, MIT; https://github.com/cktan/tomlc99), vendored unchanged
tests/test_main.c    unit tests (make test)
tests/test_vectors.json  a copy of the Python repository's tests/test_vectors.json
proxy.toml           the manifest a manager reads (name "echo-c", header version 2)
```

Threads: one accept thread, one reader thread per accepted or dialled persistent connection; handlers run on the
connection's reader thread. Every socket is non-blocking and every wait is a `poll()` that also watches a stop pipe,
so `ppc_connector_stop` wakes all threads and joins them. A TLS session is used by its reader thread and by whichever
thread writes a frame, and an OpenSSL `SSL` object must never be entered by two threads at once, so every call into
OpenSSL on a session takes the session's lock (`src/tls.c`); the lock is released while waiting on the socket. Before
that lock (2026-10-24) the first frame written after a handshake could collide with the reader processing the
server's NewSessionTicket records, which once in a few dozen TLS connections made the client read a bogus end of
stream and the connection close, seen as a flaky "secure" registration in `make test`.

## Dependencies

- gcc (C11), GNU make, pkg-config
- zlib (`pkg-config zlib`)
- OpenSSL 3 (`pkg-config openssl`): libcrypto for the AEADs and random bytes, libssl for TLS

No other library is linked; the JSON code is in `src/json.c` and the TOML parser is vendored in `third_party/tomlc99`
(chosen over writing one because manifests are TOML 1.0 documents whose strings, escapes and inline tables are
better handled by a parser that has seen them all; it compiles clean under this project's warning flags).

## Build

```
make            # build/libprotocolproxy.a, bin/echo-proxy and bin/conformance
make self-test  # bin/echo-proxy --self-test against tests/test_vectors.json
make test       # unit tests: vectors, JSON, compression, AEAD, options, stdin handshake, loopback connectors,
                # manifests, records, the authority, and the manager against bin/echo-proxy
make clean
```

`make test` builds the tests with AddressSanitizer and UndefinedBehaviorSanitizer when their runtimes link, under
valgrind with `VALGRIND=1`, and otherwise (neither installed) with gcc's `-fanalyzer`, `_FORTIFY_SOURCE=3` and
glibc's `MALLOC_CHECK_=3`; it prints which mode it used. The tests also watch heap growth over a few hundred
request/response cycles as a leak smoke test.

## Running the conformance check

Two harnesses check a proxy against PROTOCOL.md section 12, by the same 26 check names: the Python one on the Python
manager, and this port's `bin/conformance` on the C manager. A proxy is expected to pass both.

```
cd /path/to/protocol-proxy
python -m protocol_proxy.conformance /path/to/protocol-proxy-c/proxy.toml --echo ECHO --manager-dials --tls -v
```

or `make conformance` (edit `PYTHON` and `PROTOCOL_PROXY_DIR` in the Makefile or pass them on the command line).

```
bin/conformance proxy.toml --echo ECHO --tls --manager-dials                 # this port's echo proxy
bin/conformance ../protocol-proxy-go/proxy.toml --echo ECHO --tls --manager-dials
bin/conformance ../protocol-proxy-julia/proxy.toml --echo ECHO --tls --manager-dials --timeout 60
bin/conformance ../protocol-proxy/tests/manifests/GeventDummy.toml --echo ECHO --tls --manager-dials --python /path/to/venv/bin/python
bin/conformance mqtt                                                        # a manifest found on the search path
```

The Python repository ships manifests for its two test dummies in `tests/manifests/` (`GeventDummy.toml`,
`AsyncioDummy.toml`); their `[environment]` sets `PYTHONPATH = "{manifest_dir}/.."` so the dummies import from the
tests directory, and `--python` names the virtual environment that has protocol-proxy installed. `[environment]`
values get the same `{manifest_dir}` and `{python}` substitution as `command`, `{python}` being the interpreter the
manager would launch with.

Options: `--echo METHOD` (a method that replies with its payload; without it the payload checks are skipped),
`--tls`, `--manager-dials`, `--option NAME=VALUE` (a launch option, repeatable), `--timeout S` (registration and
each reply, default 20), `--python PATH` (what `{python}` resolves to), `--json`, `-v` (the manager's log and the
proxy's records on stderr). Exit code 0 when every check passes or is skipped. As of 2026-10-24 the C, Go and Julia
echo proxies and the Python gevent and asyncio test dummies pass 26 of 26 under the C manager, and the C echo proxy
passes 26 of 26 under the Python and Go managers.

## Manager

`ppc_manager` is the C `ProtocolProxyManager`: it reads a manifest, launches the proxy process, writes the tokens
(and key and TLS material) to its stdin, reads its stdout and stderr, accepts its registration, pings it, handles its
`LOG` batches, terminates it on stop and relaunches it on the next `get_proxy` after a loss. It is a connector like a
proxy (`ppc_manager_connector`), so handlers for a proxy's unsolicited pushes are registered on it the same way.

```c
char err[512];
ppc_manifest *mf = ppc_manifest_find("mqtt", err, sizeof err);          /* or ppc_manifest_load("path/proxy.toml", ...) */
ppc_manager_config cfg = {.manifest = mf, .encrypt = true, .ipc_tls = true, .persistent = true};
ppc_manager *m = ppc_manager_new(&cfg, err, sizeof err);
ppc_manager_start(m);                                                    /* listens on localhost, first free port in 22801..22899 */
ppc_manager_on_proxy_lost(m, on_lost, user);                             /* re-run setup: get_proxy + wait_registered */
const char *remote[] = {"mqtt", "broker"};
ppc_option options[] = {{"host", "broker.example"}, {"port", "1883"}, {"username", "u"}};
ppc_managed_proxy *p = ppc_manager_get_proxy(m, remote, 2, options, 3, err, sizeof err);
ppc_manager_wait_registered(m, p, 20.0);                                 /* the process is terminated and forgotten on a timeout */
ppc_message msg = {"READ_POINTS", payload, len, true, NULL, 2, false};
ppc_manager_request(m, p, &msg, 10.0, &reply, &reply_len);               /* or ppc_manager_send for no reply */
ppc_manager_set_proxy_log_level(m, p, PPC_LOG_DEBUG, 5.0, &reply, &reply_len);
char *health = ppc_manager_health_json(m);                               /* state, last seen, misses, features, pid, last PING report */
ppc_manager_stop(m, true, 5.0);                                          /* SIGTERM every proxy, SIGKILL after the timeout */
ppc_manager_free(m);                                                     /* also frees every proxy handle it returned */
```

**Configuration** (`ppc_manager_config`): `manifest` (required, must outlive the manager); `inbound_address`,
`inbound_port` (the listener; proxies are told `--manager-address inbound_address`); `persistent`, `encrypt`,
`cipher`, `ipc_tls` as defaults for every proxy, each overridable per launch through the options `persistent`,
`encrypt`, `cipher`, `ipc_tls`; `compress_threshold`; `heartbeat_interval` (10 s; negative disables the heartbeat),
`heartbeat_timeout` (5 s), `heartbeat_misses` (3); `python`; `records` and `records_user` (where the proxies' records
go, default `ppc_record_log`); `proxy_log_level` (gates them and travels as `--log-level`, default INFO); `env_names`,
`env_values`, `env_count` (added to every proxy's environment after the manifest's).

**get_proxy options** are the proxy's launch options in the Python kwargs spelling (`inbound_port`, not
`--inbound-port`), as name/value string pairs (`"true"`/`"false"` for booleans); they select the process through the
manifest's identity keys and are checked against its `must_match`, then travel to the proxy as `--name value`, sorted
by name after the standard options. The manager-only ones are `dial` (`host:port`, where to reach a `manager_dials`
proxy; default its `inbound_address:inbound_port`), `ssh_host`, `ssh_options`, `ssh_forward`, `remote_python`,
`remote_env` (the SSH launcher prefix of PROTOCOL.md section 1, composed as the Python manager composes it, with
`ssh_options` and `remote_env` as whitespace-separated lists; not exercised by the tests here) and
`manager_callbacks` (ignored; register handlers on `ppc_manager_connector(m)` instead).

**Process keys and names.** The process key is `(manifest name, *normalised identity options)` when the manifest
names `keys`, else the caller's `unique_remote_id`; a proxy's name, as passed in `--proxy-name` and used in log
lines, is that key rendered as a Python tuple (`('mqtt', 'broker.example', 1883)`), which is what a Python manager
would call the same process. The proxy id for a key is kept across relaunches; each launch gets a fresh token and,
when encrypting, a fresh key. Handles (`ppc_managed_proxy *`) stay valid until the manager is freed; a lost one
reports `ppc_managed_proxy_lost` and its reason.

**Manifest discovery** (`ppc_manifest_search_path`) is the section 1a list: the directories in
`PROTOCOL_PROXY_MANIFESTS` (prepended), `$XDG_CONFIG_HOME/protocol-proxy/manifests` (`~/.config`),
`<prefix>/share/protocol-proxy/manifests`, `$XDG_CONFIG_DIRS/protocol-proxy/manifests` (`/etc`), and
`$XDG_DATA_DIRS/protocol-proxy/manifests` (`/usr/local/share:/usr/share`). `<prefix>` is `PROTOCOL_PROXY_PREFIX`
when set, else the directory above the running executable's directory (a binary installed at `<prefix>/bin/x` looks
in `<prefix>/share`), the C counterpart of a Python environment's `sys.prefix`. There is no Python entry-point
fallback: Python proxies are found after `protocol-proxy-manifests export` has copied their manifests into one of the
directories. `ppc_manifest_find(name)`, `ppc_manifest_load(path)` and `ppc_manifest_locate(name)` are the entry
points; `ppc_manifest_parse(text, source)` builds one from TOML text.

**`{python}`** in a manifest command resolves to `cfg.python`, else `$PROTOCOL_PROXY_PYTHON`, else `python3` (behind
an SSH prefix: `remote_python`, default `python3`). `{manifest_dir}` is the manifest file's directory.

**Logging hooks.** The manager's own records go through `ppc_log` under the library's logger (`ppc_log_init` selects
text or JSON lines and the level). A launched proxy's records, whether read as JSON lines from its stderr pipe, as
plain lines from either pipe (stdout INFO, stderr WARNING, or the level of a `<N>` syslog prefix) or received in `LOG`
batches, are rebuilt as `ppc_record` (level, message, the proxy's own logger name, the channel `stdout`/`stderr`/
`socket`, pid, proxy name, the raw fields) and handed to `cfg.records`, called from the pipe reader threads and the
connector's LOG handler. The default `ppc_record_log` forwards to `ppc_log` under
`protocol_proxy.proxies.<manifest name>.<proxy name>`. Records below the proxy's level (`proxy_log_level`, changed by
`ppc_manager_set_proxy_log_level`) are dropped before the handler sees them. A `dropped` count in a batch becomes one
WARNING.

**TLS.** Every manager creates an in-memory CA (`ppc_authority`, EC P-256, 366 days) and issues itself a certificate
at `ppc_manager_new`; a proxy launched with TLS is issued one naming its id and receives `{"ca", "cert", "key"}` on
stdin. The manager's listener accepts plain and TLS connections on one port (`tls_accept_plain`; the first byte tells
them apart), so TLS and plain proxies may share a manager.

**Liveness.** Registered proxies with a running process are pinged every `heartbeat_interval`; any reply counts, and
`heartbeat_misses` consecutive misses, a process exit, or no registration within `ppc_manager_wait_registered`'s
timeout lose the proxy: it is forgotten, its process terminated (SIGTERM, SIGKILL after 5 s), the
`ppc_manager_on_proxy_lost` callbacks run, and the next `get_proxy` for its key relaunches it. A process the manager
is itself terminating is not pinged. `ppc_manager_stop` closes the listener and connections first, then terminates
every running proxy.

**Threads.** One watcher (`waitpid`, polled) and two pipe readers per launched process, one dialler per
`manager_dials` proxy until it registers, one heartbeat thread, and one terminator per lost proxy whose process is
still running. All of them poll with short timeouts and are joined by `ppc_manager_free`, which first stops the
manager. Processes are started with `posix_spawnp` and pipes opened `O_CLOEXEC`, so a child inherits only its three
standard descriptors.

The manager-side behaviours this port took from the Python reference are the ones PROTOCOL.md section 11b lists.

## Running echo-proxy by hand

```
bin/echo-proxy --self-test [--vectors tests/test_vectors.json]
bin/echo-proxy --proxy-id <hex> --proxy-name <str> --manager-id <hex> --manager-address 127.0.0.1 --manager-port 22801 \
    [--inbound-address <host>] [--inbound-port <int>] [--encrypt true|false] [--cipher auto|aes-256-gcm|chacha20-poly1305] \
    [--ipc-tls true|false] [--manager-dials true|false] [--persistent true|false] [--compress-threshold <int>] \
    [--log-level <LEVEL>] [--<protocol option> <value> ...]
```

The tokens (and the key with `--encrypt true`, the TLS JSON line with `--ipc-tls true`) are read from stdin as the
manager writes them. Unknown `--name value` options are accepted and logged. Without a manager the proxy logs
readable text; with `_LAUNCHED_BY_PROXY_MANAGER` set and stderr a pipe it logs JSON lines.

## Behaviour copied from the Python reference that PROTOCOL.md leaves implicit (proxy side)

- Request ids run 1 .. MAX-1 (Python `cycle(range(1, MAX))`), shared across peers, one counter per header version.
- A reply is sealed (compressed, encrypted) toward the peer the request came from; a frame from an unknown sender
  gets an empty, clear-text `RESPONSE` when it expected one.
- With no advertised features yet (before the registration reply) nothing is compressed toward the manager and the
  proxy's own cipher is used; once the manager's features are known, a cipher it did not advertise falls back to
  ChaCha20-Poly1305. `--cipher auto` picks AES-256-GCM when `/proc/cpuinfo` lists `aes`.
- `--compress-threshold 0` compresses every non-empty payload.
- The persistent-threshold comparison uses the full frame length after sealing (as the gevent connector does).
- A refused frame (wrong encryption mode, failed authentication, corrupt compression) drops the connection.
- `SET_LOG_LEVEL` accepts level names case-insensitively plus `WARN`, `FATAL` and numbers, and replies with the
  level in force; an unusable level gets the section 8 error reply with method `SET_LOG_LEVEL`.
- `PING` reports `uptime` rounded to milliseconds, `remotes` as the number of distinct remote ids with handlers,
  `busy` false, and `last_activity` in ISO 8601 with `+00:00`.
- Exit code 0 after SIGTERM or a lost parent even before registration; 1 when registration fails.

One deliberate difference: a `RESPONSE` is written with the header version of the request it answers (the Python
connectors always answer with version 2). The Python manager accepts both.
