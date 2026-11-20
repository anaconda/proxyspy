# Use a forward proxy

Use forward mode when the client can be told to use an HTTPS proxy. For a
single command, let proxyspy launch it. If a test harness, IDE, or separate
shell launches the client, start proxyspy with `--standalone` instead. The
HTTPS traffic follows the same route either way.

## Inspect an outgoing request

Suppose a script prints an HTTP status but you also want to know what path
it requested and which headers its HTTP library added. Here's a Python
client that prints only the status:

```sh
proxyspy -l request.log -- \
  python -c 'from urllib.request import urlopen; print(urlopen("https://www.python.org/").status)'
```

Read `request.log` in order. `[C->P] CONNECT` is the client asking proxyspy
for a tunnel to `www.python.org`. The request you care about comes **after**
the TLS handshake. Under `[C->S] GET /`, look for `Host` and `User-Agent`.
`[S->C]` is the server's reply. If requests overlap, use the connection
number (such as `0001`) to follow one exchange.

```text
Processes                    HTTPS request
shell                        Python client
  `-- proxyspy                 | CONNECT www.python.org:443, then TLS
        `-- Python client      v
                             proxyspy
                               | separate TLS connection
                               v
                             www.python.org
```

Replace everything after `--` with your command, including its arguments.
For example, `proxyspy -l tests.log -- python -m pytest` wraps a test run.
proxyspy gives the child a loopback proxy address and a temporary CA
certificate. Programs the child starts inherit those settings unless they
replace the environment. When the child exits, proxyspy closes the listener
and returns the child's exit status. Your shell's settings haven't changed.

Use test credentials: logs can contain cookies, tokens, and identifying
headers. If the test only needs to check the outgoing request, you can
[return a fixed response](options.md#give-the-client-a-known-response)
without contacting the server. That's how the [conda plugin tests](case-studies.md#check-a-plugin-generated-header) check their headers.

## Compare clients from another shell

To find out whether two HTTP libraries send the same headers, keep one proxy
running and send the same request from both. In terminal 1:

```sh
umask 077
proxyspy --standalone -l clients.log
```

Wait for the proxy address and the `source` command. In terminal 2, use the
printed environment file (the default path is shown here):

```sh
(
  . "$HOME/.proxyspy/env"
  curl -sS -o /dev/null https://www.python.org/
  python -c 'from urllib.request import urlopen; print(urlopen("https://www.python.org/").status)'
)
```

```text
Processes                         HTTPS requests (one at a time)
terminal 1: proxyspy              curl   --.
terminal 2: shell                          +--> proxyspy --> www.python.org
              |-- curl            Python --'
              `-- Python
```

Look at the two **new** `[C->S] GET /` entries in `clients.log`. Both should
show `Host: www.python.org`, but one `User-Agent` identifies curl and the other
Python. The parentheses keep the settings in a subshell; to work interactively
instead, source the file in a fresh shell and exit it afterward.

Both forward setups set `HTTP_PROXY` and `HTTPS_PROXY` (also in lower case),
clear `NO_PROXY` and `no_proxy`, and set `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`,
`SSL_CERT_FILE`, and `CONDA_SSL_VERIFY` to the CA path. For a client launched
by an IDE or service manager, give its launch configuration the printed
settings before starting it. If nothing reaches the log, check whether the
client honors those settings or used a cached response. If you need to test
the client *without* an explicit proxy, use [reverse mode](reverse.md).

Ctrl-C stops proxyspy and removes its `env` file. It doesn't unset variables
in a shell that already read the file. The standalone CA stays in `~/.proxyspy`.

## Send one hostname to a local service

Say your application calls `https://api.test/health`, but the server you are
developing listens on `http://127.0.0.1:8000`. `--map` lets your local server
answer without changing the URL, editing DNS, or configuring TLS in the
server. To try it, serve one file from an otherwise empty directory in
terminal 1:

```sh
mkdir -p fixture
printf 'healthy\n' > fixture/health
python -m http.server 8000 --bind 127.0.0.1 --directory fixture
```

In terminal 2:

```sh
proxyspy -l local.log --map api.test=http://127.0.0.1:8000 -- curl -sS https://api.test/health
```

curl prints `healthy`. Check both ends: the request in `local.log` still has
`Host: api.test`; the development server reports `GET /health`. Only the
connection from proxyspy to the development server uses plain HTTP.

```text
Processes                     Request to https://api.test/health
terminal 1: local server      curl
terminal 2: proxyspy            | CONNECT api.test:443, then TLS
              `-- curl          v
                              proxyspy
                                | HTTP to 127.0.0.1:8000
                                v
                              local server
```

Use the same `--map` with `--standalone` to try several clients. A map only
changes the destination for the named host; requests to other hosts still go
to their real servers. Run the server outside the client's proxy environment
so its own requests don't loop back to it. Stop the server with Ctrl-C when
you're done. For a working example with a Cloudflare Worker instead of a
file server, see [Test a Cloudflare Worker locally](case-studies.md#test-a-cloudflare-worker-locally).
