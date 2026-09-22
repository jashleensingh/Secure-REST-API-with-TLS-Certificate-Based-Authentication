package com.jashleen.securerest.handlers;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsExchange;

import javax.net.ssl.SSLPeerUnverifiedException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;

/**
 * TLS is still in effect here (this whole server only speaks HTTPS) — this
 * endpoint just doesn't require the CLIENT to present a certificate. The
 * TLS layer is configured with "want" client auth (see SecureApiServer),
 * so a client MAY present a cert without being forced to; this handler
 * reports whether one showed up, purely as a demonstration, without
 * gating access on it.
 */
public class PublicHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String clientCertStatus = "none presented";

        if (exchange instanceof HttpsExchange httpsExchange) {
            try {
                Certificate[] peerCerts = httpsExchange.getSSLSession().getPeerCertificates();
                clientCertStatus = peerCerts.length + " certificate(s) presented (not required or verified here)";
            } catch (SSLPeerUnverifiedException e) {
                // Expected and normal on this endpoint — no client cert is required.
            }
        }

        String body = """
                {"endpoint": "public", "message": "This endpoint requires TLS but no client certificate.", "clientCert": "%s"}
                """.formatted(clientCertStatus).trim();

        byte[] responseBytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}
