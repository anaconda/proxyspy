```
HTTPS debugging proxy that logs or intercepts HTTPS requests.

Launches a proxy server that either forwards HTTPS requests while logging
headers and content, or intercepts requests and returns specified responses.
Manages certificates automatically and supports concurrent connections.
The script relies on the cryptography library to generate SSL certificates
for the proxy, but deliberately avoids other third-party dependencies.

Arguments:
    --logfile, -l FILE    Write logs to FILE instead of stdout
    --port, -p PORT       Listen on PORT (default: 8080)
    --keep-certs          Keep certificates in current directory
    --delay TIME          Emulate a connection delay of TIME seconds
    --return-code, -r N   Return status code N for all requests
    --return-header H     Add header H to responses (can repeat)
    --return-data DATA    Return DATA as response body

Examples:
    # Log all HTTPS requests to test.log:
    ./proxy_tester.py --logfile test.log -- curl https://httpbin.org/ip

    # Return 404 for all requests, but with a half-second delay:
    ./proxy_tester.py --return-code 404 --delay 0.5 -- python my_script.py

    # Return custom response with headers and body:
    ./proxy_tester.py --return-code 200 \\
                      --return-header "Content-Type: application/json" \\
                      --return-data '{"status": "ok"}' \\
                      -- ./my_script.py
```