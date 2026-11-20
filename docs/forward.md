# Use a forward proxy

## Inspect the headers conda sends

`conda info` can tell you what conda expects its `User-Agent` to be. To check
what a channel actually receives, run a command that makes a request. From a
test installation of conda, for example:

```sh
proxyspy -l conda.log -- conda notices --override-channels -c https://repo.anaconda.com/pkgs/main
```

`--` ends proxyspy's options. Everything after it is the command to run,
including the client's own flags. By default proxyspy picks a free loopback
port, creates a temporary certificate authority (CA), and gives the child
both the proxy address and the CA certificate. Your shell's environment and
`.condarc` stay as they were.

```text
Processes                          HTTPS request
shell                              conda
  `-- proxyspy                       | CONNECT repo.anaconda.com:443, then TLS
        `-- conda                    v
                                   proxyspy
                                     | separate TLS connection
                                     v
                                   repo.anaconda.com
```

Read `conda.log` in request order. `[C->P] CONNECT` is conda asking proxyspy
for the tunnel. The `User-Agent` to inspect is on the **request inside the
tunnel**, under `[C->S] GET`, along with the path and `Host`. `[S->C]` marks
the upstream reply, including its HTTP status. Even a `429 Too Many Requests`
here is a reply from the server. Match entries by connection number (such as
`0001`) when requests overlap. The log can include identifiers,
cookies, and credentials, even in URL paths; keep it out of test artifacts
you intend to publish.

The configuration tests in
[anaconda-anon-usage](https://github.com/anaconda/anaconda-anon-usage/blob/main/tests/integration/test_config.py)
and [anaconda-ident](https://github.com/anaconda/anaconda-ident/blob/main/tests/test_config.py)
use a variation: they care whether the plugin's fields (`aau/` or `aid/`, for
example) appear in the outgoing `User-Agent`. They don't need packages back.
Here's the same check with a test channel and a fixed response:

```sh
CONDA_LOCAL_REPODATA_TTL=0 proxyspy -l plugin.log --return-code 404 -- \
  conda search --override-channels -c https://channel.test/demo fakepackage
```

The search is supposed to fail. Check `plugin.log` for the request (`[C->P]`)
and the `404 Intercepted` reply (`[P->C]`); proxyspy hasn't contacted a
channel. Plugin-specific fields depend on which plugins the conda you're
testing has installed and enabled. Setting the cache lifetime to zero makes
conda check for fresh metadata without clearing your package cache.

To wrap a whole test run, use `proxyspy -l tests.log -- python -m pytest`.
Clients the runner starts inherit its settings unless the tests replace them.
The two suites above already wrap individual commands; run them normally.
In either case proxyspy waits for its child, closes the listener, and returns
the child's exit status.

## Send a channel request to a local Worker

The goal in testing `ip-bouncer-worker` is to have a local Cloudflare Worker
answer for a channel without changing the channel URL in conda. Use a forward
proxy with `--map`. Wrangler doesn't need a certificate for the channel, and
you don't need to change DNS.

Start `wrangler dev` in your Worker project with local test bindings. Keep
Wrangler in its own shell, outside the proxy environment, so its own fetches
don't loop back to it. A Worker running locally can still call real services.
For a self-contained example, use this `worker.mjs` in an empty directory:

```js
export default {
  fetch(request) {
    const path = new URL(request.url).pathname;
    const run = request.headers.get("X-Test-Run");
    return new Response(`${request.method} ${path} (run: ${run})\n`);
  },
};
```

With Node.js and Wrangler installed, start that Worker in terminal 1:

```sh
npx wrangler dev worker.mjs --local --ip 127.0.0.1 --port 8787 --compatibility-date 2025-08-03
```

For a single request you can still use the wrapper. In terminal 2:

```sh
proxyspy -l worker.log --map repo.anaconda.com=http://127.0.0.1:8787 \
  --add-header 'X-Test-Run: local' -- \
  curl -sS https://repo.anaconda.com/pkgs/main/noarch/repodata.json
```

The example Worker replies `GET /pkgs/main/noarch/repodata.json (run: local)`.
curl asked for an HTTPS channel URL; proxyspy sent the original path and
`Host: repo.anaconda.com` over HTTP to Wrangler. `--add-header` sets the test
header on the request sent to the mapped host. It doesn't change the
response. Other hosts still reach their real servers.

### Keep the proxy running between commands

When comparing curl with conda, mamba, or pixi, it helps to leave both the
Worker and proxyspy up. In terminal 2, replace the one-shot wrapper with:

```sh
umask 077
proxyspy --standalone -l clients.log --map repo.anaconda.com=http://127.0.0.1:8787 \
  --add-header 'X-Test-Run: local'
```

Wait for proxyspy to print the proxy address and a `source` command. In a
third terminal, use the printed path (the default is shown here):

```sh
(
  . "$HOME/.proxyspy/env"
  curl -sS https://repo.anaconda.com/pkgs/main/noarch/repodata.json
)
```

```text
Processes                       Request to repo.anaconda.com
terminal 1: Wrangler / Worker   curl or conda
terminal 2: proxyspy              | CONNECT, then TLS for repo.anaconda.com
terminal 3: shell                 v
              `-- client        proxyspy
                                  | HTTP to 127.0.0.1:8787
                                  v
                                Wrangler / Worker
```

Run other client commands inside the parentheses to give them the same
environment. With a Worker that serves real channel metadata, for instance,
try `conda search --override-channels -c https://repo.anaconda.com/pkgs/main zlib`.
The example Worker above returns text, not repodata, so only use it to check
routing. Look for a **new** `CONNECT` and the expected path in `clients.log`
as you run each command. If nothing appears, the client may have used its
cache or ignored the proxy settings.

Wrapped and standalone forward mode supply the same settings: upper- and
lower-case `HTTP_PROXY` and `HTTPS_PROXY`, empty `NO_PROXY` and `no_proxy`,
and the CA path in `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`,
and `CONDA_SSL_VERIFY`. If a client ignores those settings, configure its
proxy and trusted CA explicitly. Use [reverse mode](reverse.md) if configuring
a proxy would change the behavior you want to test.

The parentheses keep the settings out of the parent shell. To drive the
client interactively instead, source the file in a fresh shell and exit that
shell when you're done. Ctrl-C stops proxyspy and removes its `env` file; it
can't unset variables in a shell that already read it. The CA stays in
`~/.proxyspy`. Stop Wrangler separately with Ctrl-C.
