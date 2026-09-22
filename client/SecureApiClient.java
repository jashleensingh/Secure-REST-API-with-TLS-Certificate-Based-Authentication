package com.jashleen.securerest;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

/**
 * Exercises the running server exactly like the curl-based tests in
 * scripts/run_demo.sh do, but through Java's own HttpsURLConnection —
 * useful as a reference for wiring an mTLS client into a real Java
 * application rather than only a shell script.
 */
public class SecureApiClient {

    private static final char[] PASSWORD = "changeit123".toCharArray();

    public static void main(String[] args) throws Exception {
        String certsDir = args.length > 0 ? args[0] : "certs";

        System.out.println("--- Calling /api/public (no client cert configured) ---");
        callWithClientCert(certsDir, null, "https://localhost:8443/api/public");

        System.out.println("\n--- Calling /api/secure WITHOUT a client cert (expect 401) ---");
        callWithClientCert(certsDir, null, "https://localhost:8443/api/secure");

        System.out.println("\n--- Calling /api/secure WITH the trusted client cert (expect 200) ---");
        callWithClientCert(certsDir, certsDir + "/client.p12", "https://localhost:8443/api/secure");
    }

    private static void callWithClientCert(String certsDir, String clientKeystorePath, String url) {
        try {
            SSLContext sslContext = buildSslContext(certsDir, clientKeystorePath);
            HttpsURLConnection connection = (HttpsURLConnection) URI.create(url).toURL().openConnection();
            connection.setSSLSocketFactory(sslContext.getSocketFactory());
            connection.setRequestMethod("GET");

            int status = connection.getResponseCode();
            InputStream stream = status < 400 ? connection.getInputStream() : connection.getErrorStream();
            String body = readAll(stream);

            System.out.println("HTTP " + status + ": " + body);
        } catch (Exception e) {
            System.out.println("Request failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static SSLContext buildSslContext(String certsDir, String clientKeystorePath) throws Exception {
        KeyStore trustStore = loadKeyStore(certsDir + "/client-truststore.p12");
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        KeyManagerFactory keyManagerFactory = null;
        if (clientKeystorePath != null) {
            KeyStore clientKeyStore = loadKeyStore(clientKeystorePath);
            keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(clientKeyStore, PASSWORD);
        }

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(
                keyManagerFactory != null ? keyManagerFactory.getKeyManagers() : null,
                trustManagerFactory.getTrustManagers(),
                null
        );
        return sslContext;
    }

    private static KeyStore loadKeyStore(String path) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(path)) {
            keyStore.load(fis, PASSWORD);
        }
        return keyStore;
    }

    private static String readAll(InputStream stream) throws Exception {
        if (stream == null) return "(no body)";
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) sb.append(line);
        }
        return sb.toString();
    }
}
