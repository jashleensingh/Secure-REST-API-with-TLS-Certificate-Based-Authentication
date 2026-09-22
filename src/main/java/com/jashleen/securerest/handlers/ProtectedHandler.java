package com.jashleen.securerest.handlers;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsExchange;
import com.jashleen.securerest.DnUtils;

import javax.net.ssl.SSLPeerUnverifiedException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.util.Set;

/**
 * Two layers of defense here, deliberately kept distinct:
 *
 * 1. TLS layer (cryptographic): the server's SSLContext is built from a
 *    trust store containing only our CA. Any client certificate NOT
 *    signed by that CA is rejected during the TLS handshake itself,
 *    before this handler — or any application code — ever runs. This is
 *    what actually stops an attacker; no amount of application logic
 *    matters if this layer is misconfigured.
 *
 * 2. Application layer (authorization): even a certificate that the TLS
 *    layer trusts (i.e., is genuinely CA-signed) still has to name an
 *    identity on ALLOWED_CLIENT_COMMON_NAMES below to get access here.
 *    This is the IAM-relevant part: authentication (proving who you are,
 *    via the cert) is necessary but not sufficient — authorization
 *    (checking whether that identity is allowed to do this) is a
 *    separate, explicit decision, exactly as it should be in a real
 *    system where not every certificate the CA ever issues should have
 *    access to every protected resource.
 */
public class ProtectedHandler implements HttpHandler {

    private static final Set<String> ALLOWED_CLIENT_COMMON_NAMES = Set.of("trusted-client-01");

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if (!(exchange instanceof HttpsExchange httpsExchange)) {
            respond(exchange, 500, "{\"error\": \"This endpoint requires HTTPS.\"}");
            return;
        }

        Certificate[] peerCerts;
        try {
            peerCerts = httpsExchange.getSSLSession().getPeerCertificates();
        } catch (SSLPeerUnverifiedException e) {
            respond(exchange, 401, "{\"error\": \"Client certificate required for this endpoint.\"}");
            return;
        }

        if (peerCerts.length == 0 || !(peerCerts[0] instanceof java.security.cert.X509Certificate cert)) {
            respond(exchange, 401, "{\"error\": \"No valid X.509 client certificate presented.\"}");
            return;
        }

        String subjectDn = cert.getSubjectX500Principal().getName();
        String commonName = DnUtils.extractCommonName(subjectDn);

        if (commonName == null || !ALLOWED_CLIENT_COMMON_NAMES.contains(commonName)) {
            respond(exchange, 403, "{\"error\": \"Certificate is valid but '" + commonName +
                    "' is not authorized for this resource.\"}");
            return;
        }

        String body = """
                {"endpoint": "secure", "message": "Access granted.", "authenticatedAs": "%s"}
                """.formatted(commonName).trim();
        respond(exchange, 200, body);
    }

    private void respond(HttpExchange exchange, int status, String jsonBody) throws IOException {
        byte[] responseBytes = jsonBody.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}
