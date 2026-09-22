package com.jashleen.securerest;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class DnUtils {

    private static final Pattern CN_PATTERN = Pattern.compile("CN=([^,]+)");

    private DnUtils() {
    }

    /** Extracts the CN field from an X.500 Subject DN string, e.g. "CN=trusted-client-01, O=Demo Org, C=CA" -> "trusted-client-01". */
    public static String extractCommonName(String subjectDn) {
        Matcher matcher = CN_PATTERN.matcher(subjectDn);
        return matcher.find() ? matcher.group(1).trim() : null;
    }
}
