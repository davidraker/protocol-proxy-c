# protocol-proxy-c

A C port of the protocol-proxy IPC library (the contract in the Python repository's `PROTOCOL.md`) and an
`echo-proxy` executable built on it. A `ProtocolProxyManager` in any language launches `echo-proxy` through the
`proxy.toml` manifest; the proxy registers, answers `PING`, `SET_LOG_LEVEL` and `ECHO`, and exits cleanly on
SIGTERM or when its parent process is gone.

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
  manager (readable text otherwise). `LOG` batches over the socket are not sent, so `log` is not advertised.
- Parent-PID watch every second and SIGTERM handling, exit code 0 on a clean stop, a 15 s hard-exit guard.

## Layout

```
include/ppc/ppc.h    public API (headers, JSON, codecs, logging, connector, proxy, self test)
src/headers.c        header pack/unpack
src/json.c           JSON parser and writer (Python json.dumps formatting)
src/codec.c          zlib, ChaCha20-Poly1305 and AES-256-GCM (OpenSSL EVP), cipher selection
src/log.c            log records (JSON lines or text) on stderr
src/tls.c            TLS material parsing and TLS 1.3 sessions over non-blocking sockets
src/connector.c      the IPC connector: listener, dialer, connections, authentication, dispatch, sending
src/proxy.c          the proxy process: command line, stdin handshake, registration, PING/SET_LOG_LEVEL, watchdog
src/selftest.c       checks every vector in tests/test_vectors.json
src/util.c           UUIDs, hex, buffers, timestamps
tools/echo-proxy.c   the executable (ECHO handler, --self-test)
tests/test_main.c    unit tests (make test)
tests/test_vectors.json  a copy of the Python repository's tests/test_vectors.json
proxy.toml           the manifest a manager reads (name "echo-c", header version 2)
```

Threads: one accept thread, one reader thread per accepted or dialled persistent connection; handlers run on the
connection's reader thread. Every socket is non-blocking and every wait is a `poll()` that also watches a stop pipe,
so `ppc_connector_stop` wakes all threads and joins them.

## Dependencies

- gcc (C11), GNU make, pkg-config
- zlib (`pkg-config zlib`)
- OpenSSL 3 (`pkg-config openssl`): libcrypto for the AEADs and random bytes, libssl for TLS

No other library is used; the JSON code is in `src/json.c`.

## Build

```
make            # build/libprotocolproxy.a and bin/echo-proxy
make self-test  # bin/echo-proxy --self-test against tests/test_vectors.json
make test       # unit tests: vectors, JSON, compression, AEAD, options, stdin handshake, loopback connectors
make clean
```

`make test` builds the tests with AddressSanitizer and UndefinedBehaviorSanitizer when their runtimes link, under
valgrind with `VALGRIND=1`, and otherwise (neither installed) with gcc's `-fanalyzer`, `_FORTIFY_SOURCE=3` and
glibc's `MALLOC_CHECK_=3`; it prints which mode it used. The tests also watch heap growth over a few hundred
request/response cycles as a leak smoke test.

## Running the conformance check

The Python harness launches the proxy through the manifest and checks every part of the contract:

```
cd /path/to/protocol-proxy
python -m protocol_proxy.conformance /path/to/protocol-proxy-c/proxy.toml --echo ECHO --manager-dials --tls -v
```

or `make conformance` (edit `PYTHON` and `PROTOCOL_PROXY_DIR` in the Makefile or pass them on the command line).
`--tls` may be included: this port implements TLS. The expected result is "all checks pass" with nothing failed.

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

## Behaviour copied from the Python reference that PROTOCOL.md leaves implicit

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
