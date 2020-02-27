package net.xenix.util;

import java.util.regex.Pattern;
import org.slf4j.Marker;

public class ValidUtil {
    public static boolean isEmpty(String value) {
        return value == null || value.isEmpty();
    }

    public static boolean isValidEmail(String value) {
        if (isEmpty(value) || !Pattern.compile("^[_a-z0-9-]+(.[_a-z0-9-]+)*@(?:\\w+\\.)+\\w+$").matcher(value.toLowerCase()).matches() || value.contains(Marker.ANY_NON_NULL_MARKER)) {
            return false;
        }
        return true;
    }

    public static boolean isValidPassword(String value) {
        if (!isEmpty(value)) {
            return Pattern.compile("^(?=.*[a-zA-Z!@#$%^&*(),.])(?=.*[a-zA-Z])(?=.*[0-9]).{6,18}$").matcher(value).matches();
        }
        return false;
    }

    public static boolean isValidUserName(String value) {
        if (!isEmpty(value)) {
            return true;
        }
        return false;
    }

    public static boolean isValidPhoneNumber(String value) {
        if (!isEmpty(value)) {
            int length = value.length();
            if (length >= 10 && length <= 11) {
                return Pattern.compile("[0-9]+").matcher(value).matches();
            }
        }
        return false;
    }
}