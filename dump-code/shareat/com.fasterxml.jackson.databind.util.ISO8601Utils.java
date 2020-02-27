package com.fasterxml.jackson.databind.util;

import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.TimeZone;

public class ISO8601Utils {
    private static final String GMT_ID = "GMT";
    private static final TimeZone TIMEZONE_GMT = TimeZone.getTimeZone(GMT_ID);

    public static TimeZone timeZoneGMT() {
        return TIMEZONE_GMT;
    }

    public static String format(Date date) {
        return format(date, false, TIMEZONE_GMT);
    }

    public static String format(Date date, boolean z) {
        return format(date, z, TIMEZONE_GMT);
    }

    public static String format(Date date, boolean z, TimeZone timeZone) {
        int length;
        GregorianCalendar gregorianCalendar = new GregorianCalendar(timeZone, Locale.US);
        gregorianCalendar.setTime(date);
        int length2 = "yyyy-MM-ddThh:mm:ss".length() + (z ? ".sss".length() : 0);
        if (timeZone.getRawOffset() == 0) {
            length = "Z".length();
        } else {
            length = "+hh:mm".length();
        }
        StringBuilder sb = new StringBuilder(length + length2);
        padInt(sb, gregorianCalendar.get(1), "yyyy".length());
        sb.append('-');
        padInt(sb, gregorianCalendar.get(2) + 1, "MM".length());
        sb.append('-');
        padInt(sb, gregorianCalendar.get(5), "dd".length());
        sb.append('T');
        padInt(sb, gregorianCalendar.get(11), "hh".length());
        sb.append(':');
        padInt(sb, gregorianCalendar.get(12), "mm".length());
        sb.append(':');
        padInt(sb, gregorianCalendar.get(13), "ss".length());
        if (z) {
            sb.append('.');
            padInt(sb, gregorianCalendar.get(14), "sss".length());
        }
        int offset = timeZone.getOffset(gregorianCalendar.getTimeInMillis());
        if (offset != 0) {
            int abs = Math.abs((offset / 60000) / 60);
            int abs2 = Math.abs((offset / 60000) % 60);
            sb.append(offset < 0 ? '-' : '+');
            padInt(sb, abs, "hh".length());
            sb.append(':');
            padInt(sb, abs2, "mm".length());
        } else {
            sb.append('Z');
        }
        return sb.toString();
    }

    /* JADX WARNING: Removed duplicated region for block: B:16:0x009a  */
    /* JADX WARNING: Removed duplicated region for block: B:31:0x011d  */
    public static Date parse(String str) {
        Exception exc;
        int i;
        int i2;
        String str2;
        try {
            int parseInt = parseInt(str, 0, 4);
            checkOffset(str, 4, '-');
            int parseInt2 = parseInt(str, 5, 7);
            checkOffset(str, 7, '-');
            int parseInt3 = parseInt(str, 8, 10);
            checkOffset(str, 10, 'T');
            int parseInt4 = parseInt(str, 11, 13);
            checkOffset(str, 13, ':');
            int parseInt5 = parseInt(str, 14, 16);
            checkOffset(str, 16, ':');
            int parseInt6 = parseInt(str, 17, 19);
            if (str.charAt(19) == '.') {
                checkOffset(str, 19, '.');
                i = 23;
                i2 = parseInt(str, 20, 23);
            } else {
                i = 19;
                i2 = 0;
            }
            char charAt = str.charAt(i);
            if (charAt == '+' || charAt == '-') {
                str2 = GMT_ID + str.substring(i);
            } else if (charAt == 'Z') {
                str2 = GMT_ID;
            } else {
                throw new IndexOutOfBoundsException("Invalid time zone indicator " + charAt);
            }
            TimeZone timeZone = TimeZone.getTimeZone(str2);
            if (!timeZone.getID().equals(str2)) {
                throw new IndexOutOfBoundsException();
            }
            GregorianCalendar gregorianCalendar = new GregorianCalendar(timeZone);
            gregorianCalendar.setLenient(false);
            gregorianCalendar.set(1, parseInt);
            gregorianCalendar.set(2, parseInt2 - 1);
            gregorianCalendar.set(5, parseInt3);
            gregorianCalendar.set(11, parseInt4);
            gregorianCalendar.set(12, parseInt5);
            gregorianCalendar.set(13, parseInt6);
            gregorianCalendar.set(14, i2);
            return gregorianCalendar.getTime();
        } catch (IndexOutOfBoundsException e) {
            exc = e;
            throw new IllegalArgumentException("Failed to parse date [" + (str == null ? null : '\"' + str + "'") + "]: " + exc.getMessage(), exc);
        } catch (NumberFormatException e2) {
            exc = e2;
            throw new IllegalArgumentException("Failed to parse date [" + (str == null ? null : '\"' + str + "'") + "]: " + exc.getMessage(), exc);
        } catch (IllegalArgumentException e3) {
            exc = e3;
            throw new IllegalArgumentException("Failed to parse date [" + (str == null ? null : '\"' + str + "'") + "]: " + exc.getMessage(), exc);
        }
    }

    private static void checkOffset(String str, int i, char c) throws IndexOutOfBoundsException {
        char charAt = str.charAt(i);
        if (charAt != c) {
            throw new IndexOutOfBoundsException("Expected '" + c + "' character but found '" + charAt + "'");
        }
    }

    private static int parseInt(String str, int i, int i2) throws NumberFormatException {
        if (i < 0 || i2 > str.length() || i > i2) {
            throw new NumberFormatException(str);
        }
        int i3 = 0;
        if (i < i2) {
            int i4 = i + 1;
            int digit = Character.digit(str.charAt(i), 10);
            if (digit < 0) {
                throw new NumberFormatException("Invalid number: " + str);
            }
            i3 = -digit;
            i = i4;
        }
        while (i < i2) {
            int i5 = i + 1;
            int digit2 = Character.digit(str.charAt(i), 10);
            if (digit2 < 0) {
                throw new NumberFormatException("Invalid number: " + str);
            }
            i3 = (i3 * 10) - digit2;
            i = i5;
        }
        return -i3;
    }

    private static void padInt(StringBuilder sb, int i, int i2) {
        String num = Integer.toString(i);
        for (int length = i2 - num.length(); length > 0; length--) {
            sb.append('0');
        }
        sb.append(num);
    }
}