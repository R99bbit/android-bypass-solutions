package net.xenix.util;

import java.text.DecimalFormat;

public class FormatUtil {
    public static String onDecimalFormat(String value) {
        return new DecimalFormat("#,###").format((long) Integer.parseInt(value));
    }

    public static String onDecimalFormat(int value) {
        return new DecimalFormat("#,###").format((long) value);
    }
}