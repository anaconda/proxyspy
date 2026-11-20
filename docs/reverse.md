# Test behind a TLS-terminating firewall

A client behind this kind of firewall asks for `https://channel.test` as
usual. The firewall answers the TLS handshake with a certificate for
`channel.test` signed by its own CA. There is no proxy URL in the client's
configuration and no HTTP `CONNECT` request. Use `--reverse` when that
difference is part of the test.

```text
Processes                      Request when forwarding
terminal 1: proxyspy           client (no proxy configured)
terminal 2: conda or curl        | TLS to loopback, SNI = channel.test
                                 v
                               proxyspy, certificate for channel.test
                                 | new TLS connection to upstream
                                 v
                               channel server
```

The client and proxyspy run independently. The client chooses the hostname;
proxyspy reads it from the TLS handshake (Server Name Indication, or SNI).
Use a hostname in the URL even when the connection goes to `127.0.0.1`.
Connecting to `https://127.0.0.1` loses the name the proxy needs.

## Make one direct request

To try this without root, DNS changes, or a system-wide trusted CA, let curl
redirect just one name and port. In terminal 1:

```sh
umask 077
proxyspy --reverse --port 8443 --intercept-host channel.test --return-data 'channel test OK'
```

Wait for `Reverse proxy listening on 127.0.0.1:8443` and the path to
`cert.pem`. In terminal 2:

```sh
curl --noproxy '*' --resolve channel.test:8443:127.0.0.1 \
  --cacert "$HOME/.proxyspy/cert.pem" https://channel.test:8443/
```

curl should print `channel test OK`. `--noproxy '*'` keeps curl on its direct
connection path even if your shell has proxy variables. `--resolve` changes
only the address curl dials, so it still checks the certificate for
`channel.test`. `--cacert` trusts the CA for this command only. The proxy log
should say `SSL handshake completed (SNI: channel.test)`. Here proxyspy makes
the reply itself, so there is no second TLS connection. Stop it with Ctrl-C.

## Why conda needed both modes

In [conda#16252](https://github.com/conda/conda/issues/16252), conda was set
to `ssl_verify: truststore`, meaning it should trust CAs in the operating
system's store. Direct connections used that setting. When an explicit proxy
was configured, Requests used a different connection manager to which conda
hadn't passed the SSL context. A certificate trusted only by the OS could
then be rejected. [The fix](https://github.com/conda/conda/pull/16253) passed
the same context to the proxy manager.

A normal `proxyspy -- conda ...` run configures both an explicit proxy and a
**CA file** for the child. A successful run that way says nothing about
whether conda used the OS trust store. Reverse mode supplied the missing
comparison: the firewall could still present a locally signed certificate
while conda made a direct connection. The curl example above checks that
routing; it doesn't test OS trust, either, because it names a CA file.

## Keep the client's usual hostname and port

For a client without curl's `--resolve`, use a disposable test machine. A
hosts-file redirect affects **every process on that machine** that resolves
the name, including applications outside your test. This example forwards to
a real conda channel. Use a test installation with no repository credentials.
In the proxy terminal, create a private directory for this run's keys:

```sh
ca_dir=$(mktemp -d)
sudo proxyspy --reverse --cert-dir "$ca_dir" --manage-hosts --prepare-host repo.anaconda.com
```

proxyspy looks up the real addresses for `repo.anaconda.com` **before** adding
its loopback redirect to `/etc/hosts`. It listens on port 443, so conda
needn't change its channel URL. On POSIX proxyspy requires root for that
port; `--manage-hosts` is POSIX-only and also requires root.

To test OS trust, add the **public** `cert.pem` at the path proxyspy prints to
the disposable machine's trust store. Don't install the private key. In a
fresh terminal with no proxy or CA-bundle variables set and no `proxy_servers`
configured in conda, run:

```sh
CONDA_SSL_VERIFY=truststore conda notices --override-channels -c https://repo.anaconda.com/pkgs/main
```

Look for a new `[C<>P]` handshake with SNI `repo.anaconda.com` and no
`CONNECT`, followed by `[P<>S]` and the request for `/pkgs/main/notices.json`.
The first handshake checks conda's trust in the test CA; for the second,
proxyspy verifies the real channel's certificate. An empty log doesn't
establish anything about trust: the request needs to reach the listener.

Ctrl-C removes this run's managed redirects. Remove the CA from the test
trust store and discard the temporary key directory. Proxyspy keeps a one-time
backup at `/etc/hosts.proxyspy.bak`. After a crash, the next `--manage-hosts`
run cleans up blocks from dead sessions. To remove **all** managed blocks,
stop other sessions first and run `sudo proxyspy --restore-hosts`.

If you manage `/etc/hosts` by hand, omit `--manage-hosts`. Start proxyspy
first, wait for its listening message, then add only the redirects it lists;
remove those lines yourself afterward. If an upstream already resolves to
loopback, remove the old redirect before starting or give proxyspy the
[intended upstream address](options.md#change-the-destination) with `--map`.
A map to proxyspy's own listening socket would loop and is rejected.
