package com.fasterxml.jackson.core;

import org.slf4j.Marker;

public final class Base64Variants {
    public static final Base64Variant MIME = new Base64Variant((String) "MIME", (String) STD_BASE64_ALPHABET, true, '=', 76);
    public static final Base64Variant MIME_NO_LINEFEEDS = new Base64Variant(MIME, "MIME-NO-LINEFEEDS", ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED);
    public static final Base64Variant MODIFIED_FOR_URL;
    public static final Base64Variant PEM = new Base64Variant(MIME, (String) "PEM", true, '=', 64);
    static final String STD_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    static {
        StringBuffer stringBuffer = new StringBuffer(STD_BASE64_ALPHABET);
        stringBuffer.setCharAt(stringBuffer.indexOf(Marker.ANY_NON_NULL_MARKER), '-');
        stringBuffer.setCharAt(stringBuffer.indexOf("/"), '_');
        MODIFIED_FOR_URL = new Base64Variant((String) "MODIFIED-FOR-URL", stringBuffer.toString(), false, 0, (int) ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED);
    }

    public static Base64Variant getDefaultVariant() {
        return MIME_NO_LINEFEEDS;
    }

    public static Base64Variant valueOf(String str) throws IllegalArgumentException {
        String str2;
        if (MIME._name.equals(str)) {
            return MIME;
        }
        if (MIME_NO_LINEFEEDS._name.equals(str)) {
            return MIME_NO_LINEFEEDS;
        }
        if (PEM._name.equals(str)) {
            return PEM;
        }
        if (MODIFIED_FOR_URL._name.equals(str)) {
            return MODIFIED_FOR_URL;
        }
        if (str == null) {
            str2 = "<null>";
        } else {
            str2 = "'" + str + "'";
        }
        throw new IllegalArgumentException("No Base64Variant with name " + str2);
    }
}