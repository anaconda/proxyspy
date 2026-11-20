# Where the proxy modes came from

## Check a plugin-generated header

The first users of proxyspy were two conda plugins. `conda info` could report
the expected `User-Agent`; the plugin developers wanted to see the header on
an actual request. The [wrapped forward proxy](forward.md#inspect-an-outgoing-request)
let their tests start conda, inspect the request and response, and leave the
calling shell alone. For example, to see what a real channel returns:

```sh
proxyspy -l conda.log -- conda notices --override-channels -c https://repo.anaconda.com/pkgs/main
```

Use a test installation without repository credentials. Look for `User-Agent`
under `[C->S] GET`, not on the `CONNECT` that precedes it, and `[S->C]` for
the upstream status. The configuration tests for
[anaconda-anon-usage](https://github.com/anaconda/anaconda-anon-usage/blob/main/tests/integration/test_config.py)
and [anaconda-ident](https://github.com/anaconda/anaconda-ident/blob/main/tests/test_config.py)
go one step further: they check for fields such as `aau/` or `aid/` in that
header, but don't need a live channel to answer. Here's the same technique
with a test hostname:

```sh
CONDA_LOCAL_REPODATA_TTL=0 proxyspy -l plugin.log --return-code 404 -- \
  conda search --override-channels -c https://channel.test/demo fakepackage
```

The search is supposed to fail. The evidence is the logged request (`[C->P]`)
and `404 Intercepted` reply (`[P->C]`), not the exit code alone. No request
goes upstream. Setting the cache lifetime to zero makes conda check for fresh
metadata. Which fields you see depends on the plugins installed and enabled.

## Test a Worker at the channel URL

In `ip-bouncer-worker` development, the server under test is a Cloudflare
Worker running locally under Wrangler. A package client should still ask for
its usual channel URL. [Mapping one hostname](forward.md#send-one-hostname-to-a-local-service)
is enough: no reverse proxy, DNS edit, or change to the client's channel list.

To try the routing without running that particular Worker, put this
`worker.mjs` in an empty directory:

```js
export default {
  fetch(request) {
    const path = new URL(request.url).pathname;
    const run = request.headers.get("X-Test-Run");
    return new Response(`${request.method} ${path} (run: ${run})\n`);
  },
};
```

With Node.js and Wrangler installed, start it in its own terminal:

```sh
npx wrangler dev worker.mjs --local --ip 127.0.0.1 --port 8787 --compatibility-date 2025-08-03
```

In another terminal, send a channel request to it:

```sh
proxyspy -l worker.log --map repo.anaconda.com=http://127.0.0.1:8787 \
  --add-header 'X-Test-Run: local' -- \
  curl -sS https://repo.anaconda.com/pkgs/main/noarch/repodata.json
```

The reply should be `GET /pkgs/main/noarch/repodata.json (run: local)`.
That checks the path and header, not whether a package can be installed: the
example returns text, not repodata. With a Worker that serves channel metadata,
use the same map [in standalone mode](forward.md#compare-clients-from-another-shell)
to compare conda, mamba, pixi, or curl. Keep Wrangler outside the proxy
environment and use test bindings: a local Worker can still call real services.

## Compare two certificate trust paths

[conda#16252](https://github.com/conda/conda/issues/16252) exposed a
difference between two connections that looked alike from the server's side.
With `ssl_verify: truststore`, a direct connection used the operating system's
trusted certificates. With an explicit proxy, Requests used another connection
manager to which conda hadn't passed the SSL context. A certificate trusted
only by the OS could then be rejected. [The fix](https://github.com/conda/conda/pull/16253)
passed the same context to the proxy manager.

A normal `proxyspy -- conda ...` run configures an explicit proxy **and a CA
file** for the child. Success with the file doesn't tell you whether conda
used the system store. [Reverse mode](reverse.md) supplied the missing
comparison: the firewall still presented a locally signed certificate, but
conda made a direct connection.

For that direct case, follow the [hostname and port setup](reverse.md#keep-the-clients-usual-hostname-and-port)
on a disposable machine with `--prepare-host repo.anaconda.com` in place of
`--prepare-host example.org`. Trust the public `cert.pem` in the OS store.
In a clean shell with no proxy or CA-bundle variables and no `proxy_servers`
configured in conda, run:

```sh
CONDA_SSL_VERIFY=truststore conda notices --override-channels -c https://repo.anaconda.com/pkgs/main
```

A new handshake with SNI `repo.anaconda.com`, followed by a request for
`/pkgs/main/notices.json` and no `CONNECT`, shows that conda reached the
listener on the direct path. Stop the proxy and remove the test CA afterward.
