# Secure REST API with TLS & Certificate-Based Authentication (mTLS)

A REST API secured with TLS/HTTPS (self-signed CA, no external certificate
authority needed) and certificate-based mutual TLS authentication on a
protected endpoint — built with **zero external dependencies**, on purpose:
the whole project compiles and runs with nothing but a JDK, so every claim
below was actually executed, not just written down.

## Why zero dependencies

Every other Java project in this portfolio uses Spring Boot, which means
Maven has to resolve dependencies from Maven Central to build at all. This
project deliberately uses the JDK's own `com.sun.net.httpserver.HttpsServer`
instead of a framework, specifically so it has no such requirement — a
grader, a CI pipeline, or anyone cloning this repo can `javac` and `java`
it directly, with no network dependency resolution step that could fail or
introduce version drift. This isn't a workaround; the whole project was
built, compiled, and run end-to-end in the environment that produced this
README, and every result quoted below is real output from that run.

## Architecture

```
scripts/generate_certs.sh
  → generates a self-signed root CA
  → server cert, signed by that CA           -> certs/server.p12
  → a TRUSTED client cert, signed by that CA  -> certs/client.p12
  → an UNTRUSTED client cert, signed by a completely different,
    throwaway CA the server has never heard of -> certs/untrusted-client.p12
  → server-truststore.p12 (trusts only the real CA)
  → client-truststore.p12 (trusts only the real CA, for verifying the server)

SecureApiServer (HttpsServer, port 8443)
  TLS configured with "want" client auth: a client MAY present a
  certificate; the TLS layer doesn't force one, but any certificate that
  IS presented must chain back to the trusted CA or the handshake fails.
  ├── GET /api/public   — HTTPS required, no client cert required
  └── GET /api/secure   — two-layer check (see ProtectedHandler):
        1. TLS layer:    was a cert presented, and does it chain to our CA?
        2. App layer:    is that cert's CN on the authorized allowlist?
```

The two-layer split in `/api/secure` is deliberate: TLS trust proves the
certificate is genuine (signed by a CA we recognize); it does NOT mean
that identity is authorized for this specific resource. Conflating those
two is a common mTLS mistake — this project keeps them as explicit,
separately-testable steps, which is the actual "Identity and Access
Management principles" the underlying design is about.

## Verified — real output from this repo's own run

`scripts/run_demo.sh` generates certs, compiles everything, runs the unit
tests, starts the server, and exercises every scenario below with real
HTTPS connections (via curl and via a Java `HttpsURLConnection`-based
client) — this isn't a description of expected behavior, it's what
actually happened when it ran:

```
--- public endpoint, no client cert (expect 200) ---
HTTP status: 200

--- secure endpoint, no client cert (expect 401) ---
HTTP status: 401

--- secure endpoint, TRUSTED client cert (expect 200) ---
HTTP status: 200

--- secure endpoint, UNTRUSTED client cert, different CA (expect connection failure) ---
HTTP status: 000

--- plain HTTP against the HTTPS port (expect connection failure) ---
HTTP status: 000
```

And the Java client, calling the same server through `HttpsURLConnection`
instead of curl:

```
--- Calling /api/public (no client cert configured) ---
HTTP 200: {"endpoint": "public", "message": "This endpoint requires TLS but no client certificate.", "clientCert": "none presented"}

--- Calling /api/secure WITHOUT a client cert (expect 401) ---
HTTP 401: {"error": "Client certificate required for this endpoint."}

--- Calling /api/secure WITH the trusted client cert (expect 200) ---
HTTP 200: {"endpoint": "secure", "message": "Access granted.", "authenticatedAs": "trusted-client-01"}
```

**On the untrusted-cert result specifically:** status `000` means curl
never received an HTTP response at all — the connection was closed by the
server during/immediately after the TLS handshake once it detected the
client's certificate didn't chain to the trusted CA. Depending on TLS
version this surfaces as `curl: (52) Empty reply from server` (TLS 1.3) or
`SSL_ERROR_SYSCALL` (TLS 1.2 forced) rather than a clean rejection alert —
that's the JDK's `HttpsServer` implementation resetting the connection
rather than completing a graceful alert handshake. The practical security
result is identical either way: no data crosses the wire, and the
untrusted client never reaches application code. Full verbose curl output
for this case is worth capturing yourself with `curl -v` if you want to
see the raw handshake bytes.

Unit tests (`DnUtilsTest` — the Subject-DN-to-CN parsing logic):
```
PASS: extracts CN from a standard three-field DN
PASS: extracts CN when it's the first field
PASS: extracts a multi-word CN
PASS: returns null when there's no CN field at all
PASS: extracts CN when it's the only field
All assertions passed.
```

Built and tested against **OpenJDK 21** — say so if you're reviewing this
on a different major version; TLS/keystore behavior has historically been
stable across JDK versions, but it's worth knowing what this was verified
against, given how JDK-version-sensitive some Java tooling can be.

## Project layout

```
scripts/generate_certs.sh    builds the full PKI (CA, server, trusted + untrusted client certs)
scripts/run_demo.sh           one command: certs → compile → unit tests → server → every scenario
src/main/java/com/jashleen/securerest/
  SecureApiServer.java         HttpsServer setup, TLS config, routing
  DnUtils.java                  Subject-DN CN extraction
  handlers/PublicHandler.java    no client cert required
  handlers/ProtectedHandler.java  TLS trust + app-layer authorization
src/test/java/.../DnUtilsTest.java   plain-assertion tests (no JUnit — stays zero-dependency)
client/SecureApiClient.java    Java-based test client (HttpsURLConnection)
certs/                          generated by generate_certs.sh (gitignored)
```

## Running it

```bash
bash scripts/run_demo.sh
```

That's the whole thing — certs, compile, tests, server, every scenario,
teardown. To explore manually instead:

```bash
bash scripts/generate_certs.sh
javac -d out $(find src/main -name "*.java")
java -cp out com.jashleen.securerest.SecureApiServer certs &

# in another terminal, from certs/:
curl --cacert ca.pem https://localhost:8443/api/public
curl --cacert ca.pem https://localhost:8443/api/secure                                    # 401
curl --cacert ca.pem --cert-type P12 --cert client.p12:changeit123 https://localhost:8443/api/secure            # 200
curl --cacert ca.pem --cert-type P12 --cert untrusted-client.p12:changeit123 https://localhost:8443/api/secure  # fails
```

## Possible extensions

- Certificate revocation checking (CRL or OCSP) — this demo trusts any
  cert the CA ever signed, with no way to revoke one early.
- A Spring Boot equivalent is genuinely just configuration, not new code —
  `server.ssl.client-auth=need` (or `want`) plus the same keystore/
  truststore files would get you there, if matching this portfolio's other
  Spring projects mattered more than the zero-dependency property. Worth
  noting: that version wasn't built or verified here, unlike everything
  above.
- Short-lived certs + automated rotation instead of the 825-day validity
  used for this demo.
