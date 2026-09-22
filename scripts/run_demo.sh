#!/usr/bin/env bash
# Regenerates certs, compiles everything, starts the server, runs the full
# test matrix (public access / missing cert / trusted cert / untrusted
# cert / plain HTTP against the TLS port), runs the unit tests, then shuts
# the server down. Zero external dependencies — just a JDK and curl.

set -euo pipefail
cd "$(dirname "$0")/.."

echo "############################################"
echo "# 1. Generating certificates"
echo "############################################"
bash scripts/generate_certs.sh

echo
echo "############################################"
echo "# 2. Compiling (server, client, tests)"
echo "############################################"
rm -rf out
mkdir -p out
javac -d out $(find src/main -name "*.java")
javac -cp out -d out client/SecureApiClient.java
javac -cp out -d out src/test/java/com/jashleen/securerest/DnUtilsTest.java
echo "Compiled cleanly."

echo
echo "############################################"
echo "# 3. Unit tests (DnUtils)"
echo "############################################"
java -cp out com.jashleen.securerest.DnUtilsTest

echo
echo "############################################"
echo "# 4. Starting the server"
echo "############################################"
java -cp out com.jashleen.securerest.SecureApiServer certs &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
sleep 2

cd certs

echo
echo "############################################"
echo "# 5. curl-based scenario tests"
echo "############################################"

echo "--- public endpoint, no client cert (expect 200) ---"
curl -s -o /dev/null -w "HTTP status: %{http_code}\n" --cacert ca.pem https://localhost:8443/api/public

echo "--- secure endpoint, no client cert (expect 401) ---"
curl -s -o /dev/null -w "HTTP status: %{http_code}\n" --cacert ca.pem https://localhost:8443/api/secure

echo "--- secure endpoint, TRUSTED client cert (expect 200) ---"
curl -s -o /dev/null -w "HTTP status: %{http_code}\n" --cacert ca.pem --cert-type P12 --cert client.p12:changeit123 https://localhost:8443/api/secure

echo "--- secure endpoint, UNTRUSTED client cert (expect connection failure, not a 200/401/403) ---"
curl -s -o /dev/null -w "HTTP status: %{http_code}\n" --cacert ca.pem --cert-type P12 --cert untrusted-client.p12:changeit123 https://localhost:8443/api/secure || true

echo "--- plain HTTP against the HTTPS port (expect connection failure) ---"
curl -s -o /dev/null -w "HTTP status: %{http_code}\n" http://localhost:8443/api/public || true

cd ..

echo
echo "############################################"
echo "# 6. Java client (HttpsURLConnection-based)"
echo "############################################"
java -cp out com.jashleen.securerest.SecureApiClient certs

echo
echo "All scenarios completed."
