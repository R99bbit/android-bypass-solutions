package com.igaworks.adbrix.util;

import java.util.regex.Pattern;

public class ADBrixUtil {
    public static boolean validateEmailFormat(String email) {
        if (email == null) {
            return false;
        }
        return Pattern.matches("[\\w\\~\\-\\.]+@[\\w\\~\\-]+(\\.[\\w\\~\\-]+)+", email.trim());
    }
}