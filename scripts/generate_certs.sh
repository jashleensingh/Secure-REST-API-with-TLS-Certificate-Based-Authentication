#!/usr/bin/env bash
# Generates the certificate chain this project's mTLS demo needs:
#   1. A self-signed CA (the root of trust)
#   2. A server key pair, signed by the CA -> server.p12
#   3. A client key pair, signed by the CA -> client.p12
#   4. A server truststore containing only the CA cert (so the server
#      trusts any client cert the CA signed, and rejects everything else)
#   5. A client truststore containing the CA cert (so the client trusts
#      the server's cert)
#   6. An UNTRUSTED client cert, signed by a completely different,
#      throwaway CA — used to prove the server actually rejects a
#      certificate that isn't in its chain of trust, not just "any cert"
#
# All output goes in certs/ (gitignored — these are demo certs with a
# hardcoded password, never meant to protect anything real).

set -euo pipefail
cd "$(dirname "$0")/.."

CERTS_DIR="certs"
PASS="changeit123"
VALIDITY_DAYS=825

rm -rf "$CERTS_DIR"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "== 1. Root CA =="
keytool -genkeypair -alias ca -keyalg RSA -keysize 2048 -validity $VALIDITY_DAYS \
    -storetype PKCS12 -keystore ca.p12 -storepass "$PASS" -keypass "$PASS" \
    -dname "CN=Jashleen Demo CA, O=Demo Org, C=CA" \
    -ext bc:c=ca:true

keytool -exportcert -alias ca -keystore ca.p12 -storepass "$PASS" -rfc -file ca.pem

echo "== 2. Server key pair + CSR, signed by the CA =="
keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -validity $VALIDITY_DAYS \
    -storetype PKCS12 -keystore server.p12 -storepass "$PASS" -keypass "$PASS" \
    -dname "CN=localhost, O=Demo Org, C=CA" \
    -ext san=dns:localhost,ip:127.0.0.1

keytool -certreq -alias server -keystore server.p12 -storepass "$PASS" -file server.csr

keytool -gencert -alias ca -keystore ca.p12 -storepass "$PASS" \
    -infile server.csr -outfile server.pem -validity $VALIDITY_DAYS \
    -ext san=dns:localhost,ip:127.0.0.1

# Rebuild the server keystore's chain: leaf cert (now CA-signed) + the CA cert itself
keytool -importcert -alias ca -keystore server.p12 -storepass "$PASS" -file ca.pem -noprompt
keytool -importcert -alias server -keystore server.p12 -storepass "$PASS" -file server.pem -noprompt

echo "== 3. Client key pair + CSR, signed by the CA (this is the TRUSTED client) =="
keytool -genkeypair -alias client -keyalg RSA -keysize 2048 -validity $VALIDITY_DAYS \
    -storetype PKCS12 -keystore client.p12 -storepass "$PASS" -keypass "$PASS" \
    -dname "CN=trusted-client-01, O=Demo Org, C=CA"

keytool -certreq -alias client -keystore client.p12 -storepass "$PASS" -file client.csr

keytool -gencert -alias ca -keystore ca.p12 -storepass "$PASS" \
    -infile client.csr -outfile client.pem -validity $VALIDITY_DAYS

keytool -importcert -alias ca -keystore client.p12 -storepass "$PASS" -file ca.pem -noprompt
keytool -importcert -alias client -keystore client.p12 -storepass "$PASS" -file client.pem -noprompt

echo "== 4. Server truststore (trusts the CA -> trusts anything the CA signed) =="
keytool -importcert -alias ca -keystore server-truststore.p12 -storepass "$PASS" \
    -file ca.pem -storetype PKCS12 -noprompt

echo "== 5. Client truststore (trusts the server's CA-signed cert) =="
keytool -importcert -alias ca -keystore client-truststore.p12 -storepass "$PASS" \
    -file ca.pem -storetype PKCS12 -noprompt

echo "== 6. Untrusted client cert, signed by a throwaway CA the server does NOT trust =="
keytool -genkeypair -alias rogue-ca -keyalg RSA -keysize 2048 -validity $VALIDITY_DAYS \
    -storetype PKCS12 -keystore rogue-ca.p12 -storepass "$PASS" -keypass "$PASS" \
    -dname "CN=Rogue CA, O=Not Trusted, C=CA" -ext bc:c=ca:true
keytool -exportcert -alias rogue-ca -keystore rogue-ca.p12 -storepass "$PASS" -rfc -file rogue-ca.pem

keytool -genkeypair -alias untrusted-client -keyalg RSA -keysize 2048 -validity $VALIDITY_DAYS \
    -storetype PKCS12 -keystore untrusted-client.p12 -storepass "$PASS" -keypass "$PASS" \
    -dname "CN=untrusted-client, O=Not Trusted, C=CA"
keytool -certreq -alias untrusted-client -keystore untrusted-client.p12 -storepass "$PASS" -file untrusted-client.csr
keytool -gencert -alias rogue-ca -keystore rogue-ca.p12 -storepass "$PASS" \
    -infile untrusted-client.csr -outfile untrusted-client.pem -validity $VALIDITY_DAYS
keytool -importcert -alias rogue-ca -keystore untrusted-client.p12 -storepass "$PASS" -file rogue-ca.pem -noprompt
keytool -importcert -alias untrusted-client -keystore untrusted-client.p12 -storepass "$PASS" -file untrusted-client.pem -noprompt

rm -f server.csr server.pem client.csr client.pem untrusted-client.csr untrusted-client.pem rogue-ca.pem

echo
echo "Done. Generated in $CERTS_DIR/:"
echo "  server.p12              - server's private key + CA-signed cert (server uses this)"
echo "  server-truststore.p12    - CA cert only (server uses this to validate client certs)"
echo "  client.p12                - TRUSTED client's private key + CA-signed cert"
echo "  client-truststore.p12      - CA cert only (client uses this to validate the server's cert)"
echo "  untrusted-client.p12         - client cert signed by a DIFFERENT CA the server doesn't trust"
echo "  ca.p12, ca.pem                  - the root CA itself"
echo
echo "Keystore/truststore password for all of the above: $PASS"
