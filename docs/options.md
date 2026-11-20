# Change what happens to a request

First choose how the client reaches proxyspy: by [forward proxy](forward.md)
or [direct TLS connection](reverse.md). The options below work with either.
By default, proxyspy logs the exchange and forwards it to the server the
client asked for.

## Give the client a known response

To see how a client handles a service outage, have proxyspy answer for the
server. This example stays on your machine; `channel.test` doesn't need DNS:

```sh
proxyspy --intercept-host channel.test --return-code 503 \
  --return-header 'Retry-After: 10' --return-data 'try again' \
  -- curl -si https://channel.test/notices.json
```

Look for `HTTP/1.1 503 Intercepted`, the `Retry-After` header, and `try again`.
With curl, you may also see `200 Connection Established`: that's the forward
proxy accepting the tunnel, not the status of the request inside it.

Any `--return-*` option turns on canned responses. The defaults are status
`200` and an empty body; repeat `--return-header` for multiple headers. The
header belongs to proxyspy's **replacement response**. It does not get added
to a reply from the real server.

Without `--intercept-host`, the canned response applies to every host that
reaches the proxy. Repeat `--intercept-host` to select several; other hosts
are still forwarded and logged. On its own, `--intercept-host` does not turn
on canned responses or filter the log. A canned response makes no upstream
connection, even if that host also has a `--map` entry.

## Change the destination

Use `--map HOST=UPSTREAM` when you want a different server to answer, as in
the [local Worker example](forward.md#send-a-channel-request-to-a-local-worker).
The client still asks for `HOST`. The mapping changes where proxyspy dials;
it doesn't rewrite the path or `Host` header.

| Upstream | Connection from proxyspy |
| --- | --- |
| `IP` | TLS to that address, using the client's `CONNECT` port in forward mode or `--upstream-port` in reverse mode (default `443`). |
| `IP:PORT` | TLS to that address and port. |
| `https://name[:port]` | TLS, default port `443`. |
| `http://name[:port]` | Plain HTTP, default port `80`. Use loopback for a local test service. |

Use a hostname, not a URL, on the left. Matching ignores case and covers all
ports on that host. Repeat `--map` for more hosts. A target URL can include an
address and port, but no credentials, path prefix, query, or fragment. For a
TLS upstream, the certificate must be valid for the **original hostname** and
trusted by the proxy process. The client's trust in proxyspy's CA is separate.

## Set a header on the way to a local service

With `--map`, add `--add-header 'X-Test-Run: local'` to set a request header
on traffic to **all mapped hosts**. Unmapped hosts don't receive it. The log
shows the rewritten request, so leave this option out when checking what the
client itself sent.

The option replaces any client header of the same name, ignoring case. Repeat
it for several headers; for the same name the last value wins. It applies to
each HTTP/1.x request on a reused connection. A body with a `Content-Length`
passes through unchanged. You can't set `Content-Length` or `Transfer-Encoding`.

For a chunked upload or a protocol upgrade, proxyspy sets the headers on the
current request if it can parse them, then logs a warning and passes through
the rest of the connection unchanged. An unparseable request head also puts
that connection into passthrough. `--add-header` never rewrites responses.

## Delay the handshake

Add `--delay 0.5` to make a new connection wait until half a second has
elapsed before the client TLS handshake. This exercises connection timeouts;
it doesn't slow individual responses or simulate a bandwidth limit.
`--prepare-host HOST` generates a host certificate at startup so that the
first connection doesn't have to wait for key generation. Mapped hosts are
already prepared.

## Ports, logs, and certificates

| Option | When to use it |
| --- | --- |
| `-p PORT`, `--port PORT` | Choose a fixed listener on `127.0.0.1`. Forward mode picks a free port by default; reverse mode uses `443`. `--port 0` picks a free port in either. |
| `-l FILE`, `--logfile FILE` | Append proxy logs to a file instead of mixing them with the client's output on stdout. `--debug` adds diagnostic messages. |
| `--cert-dir DIR` | Keep and reuse the CA and host certificates in a private directory. Use a different directory per simultaneous standalone forward run, since each writes its own `env` file. |
| `--keep-certs` | Keep a wrapped forward run's certificates in the working directory instead of deleting its temporary directory. Avoid using a source checkout: the files include private keys. |

Both standalone modes default to `~/.proxyspy`. Use an absolute path for
`--cert-dir` if clients run from a different directory. `cert.pem` is the
public CA certificate; keep `key.pem` and the host private keys to yourself.
If you installed the CA in a trust store, remove it there when you're done;
deleting the files doesn't revoke that trust.
