# Test behind a TLS-terminating firewall

Use `--reverse` when you need to know what a client does on a **direct HTTPS
connection**. A forward proxy would make the client send `CONNECT` instead.
Here the client asks for the service by name as usual, but connects to
proxyspy on loopback. Like a TLS-terminating firewall, proxyspy presents a
certificate for the service signed by its own certificate authority (CA).

```text
Processes                   Request when forwarding
terminal 1: proxyspy        client (no proxy configured)
terminal 2: your client       | TLS to loopback, SNI = api.test
                              v
                            proxyspy, certificate for api.test
                              | new TLS connection to upstream
                              v
                            server
```

The client runs independently of proxyspy. Use the service hostname in the
URL: proxyspy reads that name from the TLS handshake (Server Name Indication,
or SNI). Replacing it with `https://127.0.0.1` loses the name you're testing.

## Make one direct request

curl can redirect one name and port without root, DNS changes, or a
system-wide trusted CA. In terminal 1, start a listener that answers for
`api.test`:

```sh
umask 077
proxyspy --reverse --port 8443 --intercept-host api.test --return-data 'service OK'
```

Wait for `Reverse proxy listening on 127.0.0.1:8443`. In terminal 2:

```sh
curl --noproxy '*' --resolve api.test:8443:127.0.0.1 \
  --cacert "$HOME/.proxyspy/cert.pem" https://api.test:8443/health
```

curl should print `service OK`. `--noproxy '*'` makes it connect directly
even if your shell has proxy variables. `--resolve` changes the address curl
dials, not the name on the certificate it checks. `--cacert` trusts proxyspy's
CA for this command only. Look for `SSL handshake completed (SNI: api.test)`
in the log, followed by `GET /health`, with no `CONNECT`. There is no upstream
connection in this example: proxyspy supplied the reply. Stop it with Ctrl-C.

## Keep the client's usual hostname and port

Some clients can't override DNS for a single request. To try one without
changing its URL, use a disposable test machine: a hosts-file redirect
affects **every process on that machine** that resolves the name. This
example forwards to a real HTTPS server. In the proxy terminal:

```sh
ca_dir=$(mktemp -d)
sudo proxyspy --reverse --cert-dir "$ca_dir" --manage-hosts --prepare-host example.org
```

proxyspy looks up the real addresses for `example.org` **before** adding its
loopback redirect to `/etc/hosts`. It listens on the usual HTTPS port, 443.
On POSIX proxyspy requires root for that port; `--manage-hosts` is POSIX-only
and also requires root.

Run your client in a separate terminal without an explicit proxy configured.
For a routing check with curl, substitute the printed CA path below:

```sh
curl --noproxy '*' --cacert /path/from/proxyspy/cert.pem -I https://example.org/
```

This time you should see **two** handshakes: `[C<>P]` with SNI `example.org`,
then `[P<>S]` as proxyspy verifies the real server's certificate. If you're
testing whether your application uses the **operating system's trust store**,
install the public `cert.pem` in the test machine's store and have the client
use that store, not a CA file override. Keep verification on. The difference
matters: see [Why conda needed both modes](case-studies.md#compare-two-certificate-trust-paths).

Ctrl-C removes this run's managed redirects. Remove any trust you added and
discard the temporary key directory. After a crash, the next `--manage-hosts`
run cleans up blocks from dead sessions. To remove **all** managed blocks,
stop other sessions first and run `sudo proxyspy --restore-hosts`. proxyspy
keeps a one-time backup at `/etc/hosts.proxyspy.bak`.

If you manage `/etc/hosts` by hand, omit `--manage-hosts`. Start proxyspy
first, wait for its listening message, then add only the redirects it lists;
remove those lines yourself afterward. If an upstream already resolves to
loopback, remove the old redirect before starting or give proxyspy the
[intended upstream address](options.md#change-the-destination) with `--map`.
A map to proxyspy's own listening socket would loop and is rejected.
