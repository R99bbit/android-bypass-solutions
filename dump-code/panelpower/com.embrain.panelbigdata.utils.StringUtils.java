package com.embrain.panelbigdata.utils;

import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;

public class StringUtils {
    public static boolean isEmpty(Object obj) {
        if (obj instanceof String) {
            return "".equals((String) obj);
        }
        return true;
    }

    public static boolean isYn(String str) {
        if (isEmpty(str)) {
            return false;
        }
        return str.equalsIgnoreCase("y");
    }

    public static String getCommaValue(String str) {
        if (isEmpty(str)) {
            return "0";
        }
        return new DecimalFormat("#,###").format((long) Integer.parseInt(str));
    }

    public static String getYYYY_MM_DD(String str) {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        try {
            return new SimpleDateFormat("yyyy-MM-dd").format(simpleDateFormat.parse(str));
        } catch (Exception unused) {
            return "";
        }
    }

    public static String getTodayFull() {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Calendar.getInstance().getTime());
    }
}