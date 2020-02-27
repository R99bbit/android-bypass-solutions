package org.jboss.netty.util.internal;

import com.facebook.appevents.AppEventsConstants;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public final class ConversionUtil {
    private static final Pattern ARRAY_DELIM = Pattern.compile("[, \\t\\n\\r\\f\\e\\a]");
    private static final String[] INTEGERS = {AppEventsConstants.EVENT_PARAM_VALUE_NO, AppEventsConstants.EVENT_PARAM_VALUE_YES, "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15"};

    public static int toInt(Object value) {
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return Integer.parseInt(String.valueOf(value));
    }

    public static boolean toBoolean(Object value) {
        if (value instanceof Boolean) {
            return ((Boolean) value).booleanValue();
        }
        if (!(value instanceof Number)) {
            String s = String.valueOf(value);
            if (s.length() == 0) {
                return false;
            }
            try {
                if (Integer.parseInt(s) == 0) {
                    return false;
                }
                return true;
            } catch (NumberFormatException e) {
                switch (Character.toUpperCase(s.charAt(0))) {
                    case 'T':
                    case 'Y':
                        return true;
                    default:
                        return false;
                }
            }
        } else if (((Number) value).intValue() == 0) {
            return false;
        } else {
            return true;
        }
    }

    public static String[] toStringArray(Object value) {
        if (value instanceof String[]) {
            return (String[]) value;
        }
        if (!(value instanceof Iterable)) {
            return ARRAY_DELIM.split(String.valueOf(value));
        }
        List<String> answer = new ArrayList<>();
        for (Object v : (Iterable) value) {
            if (v == null) {
                answer.add(null);
            } else {
                answer.add(String.valueOf(v));
            }
        }
        return (String[]) answer.toArray(new String[answer.size()]);
    }

    public static String toString(int value) {
        if (value < 0 || value >= INTEGERS.length) {
            return Integer.toString(value);
        }
        return INTEGERS[value];
    }

    private ConversionUtil() {
    }
}