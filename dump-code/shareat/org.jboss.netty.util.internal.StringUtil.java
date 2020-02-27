package org.jboss.netty.util.internal;

import java.util.ArrayList;
import java.util.Formatter;
import java.util.List;

public final class StringUtil {
    private static final String EMPTY_STRING = "";
    public static final String NEWLINE;

    private StringUtil() {
    }

    static {
        String newLine;
        try {
            newLine = new Formatter().format("%n", new Object[0]).toString();
        } catch (Exception e) {
            newLine = "\n";
        }
        NEWLINE = newLine;
    }

    public static String stripControlCharacters(Object value) {
        if (value == null) {
            return null;
        }
        return stripControlCharacters(value.toString());
    }

    public static String stripControlCharacters(String value) {
        if (value == null) {
            return null;
        }
        boolean hasControlChars = false;
        int i = value.length() - 1;
        while (true) {
            if (i < 0) {
                break;
            } else if (Character.isISOControl(value.charAt(i))) {
                hasControlChars = true;
                break;
            } else {
                i--;
            }
        }
        if (!hasControlChars) {
            return value;
        }
        StringBuilder buf = new StringBuilder(value.length());
        int i2 = 0;
        while (i2 < value.length() && Character.isISOControl(value.charAt(i2))) {
            i2++;
        }
        boolean suppressingControlChars = false;
        while (i2 < value.length()) {
            if (Character.isISOControl(value.charAt(i2))) {
                suppressingControlChars = true;
            } else {
                if (suppressingControlChars) {
                    suppressingControlChars = false;
                    buf.append(' ');
                }
                buf.append(value.charAt(i2));
            }
            i2++;
        }
        return buf.toString();
    }

    public static String[] split(String value, char delim) {
        int end = value.length();
        List<String> res = new ArrayList<>();
        int start = 0;
        for (int i = 0; i < end; i++) {
            if (value.charAt(i) == delim) {
                if (start == i) {
                    res.add("");
                } else {
                    res.add(value.substring(start, i));
                }
                start = i + 1;
            }
        }
        if (start == 0) {
            res.add(value);
        } else if (start != end) {
            res.add(value.substring(start, end));
        } else {
            int i2 = res.size() - 1;
            while (i2 >= 0 && res.get(i2).length() == 0) {
                res.remove(i2);
                i2--;
            }
        }
        return (String[]) res.toArray(new String[res.size()]);
    }
}