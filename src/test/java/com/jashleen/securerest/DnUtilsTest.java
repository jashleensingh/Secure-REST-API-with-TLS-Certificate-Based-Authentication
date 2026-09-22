package com.jashleen.securerest;

/**
 * Deliberately not JUnit: this project's whole point is being buildable
 * and verifiable with nothing but a JDK, and pulling in a test framework
 * would mean a Maven/Gradle dependency resolution step for a project that
 * otherwise needs none. Run with:
 *   java -cp out com.jashleen.securerest.DnUtilsTest
 * Exits non-zero (and prints which assertion failed) on any failure, so
 * it's CI-friendly despite being plain Java.
 */
public class DnUtilsTest {

    private static int failures = 0;

    public static void main(String[] args) {
        assertEquals("trusted-client-01",
                DnUtils.extractCommonName("CN=trusted-client-01, O=Demo Org, C=CA"),
                "extracts CN from a standard three-field DN");

        assertEquals("localhost",
                DnUtils.extractCommonName("CN=localhost, O=Demo Org, C=CA"),
                "extracts CN when it's the first field");

        assertEquals("Jashleen Demo CA",
                DnUtils.extractCommonName("CN=Jashleen Demo CA, O=Demo Org, C=CA"),
                "extracts a multi-word CN");

        assertEquals(null,
                DnUtils.extractCommonName("O=Demo Org, C=CA"),
                "returns null when there's no CN field at all");

        assertEquals("only-field",
                DnUtils.extractCommonName("CN=only-field"),
                "extracts CN when it's the only field");

        if (failures > 0) {
            System.out.println("\n" + failures + " assertion(s) FAILED.");
            System.exit(1);
        }
        System.out.println("All assertions passed.");
    }

    private static void assertEquals(String expected, String actual, String description) {
        boolean pass = expected == null ? actual == null : expected.equals(actual);
        if (pass) {
            System.out.println("PASS: " + description);
        } else {
            System.out.println("FAIL: " + description + " -- expected [" + expected + "] but got [" + actual + "]");
            failures++;
        }
    }
}
