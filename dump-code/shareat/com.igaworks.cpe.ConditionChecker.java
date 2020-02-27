package com.igaworks.cpe;

import android.content.Context;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Build.VERSION;
import android.telephony.TelephonyManager;
import android.view.WindowManager;
import com.igaworks.core.RequestParameter;
import com.igaworks.dao.AbstractCPEImpressionDAO;
import com.igaworks.dao.CPEImpressionDAOFactory;
import com.igaworks.dao.CounterDAOForAllActivity;
import java.util.Collection;
import java.util.Date;
import java.util.Locale;

public class ConditionChecker {
    public static final int CPE_TYPE_NOTI = 3;
    public static final int CPE_TYPE_REWARD = 2;
    public static final String KEY_ACTIVITY_GROUP_DELIMETER = "::--::";
    public static final String KEY_APP_LAUNCH_COUNT = "app_launch_count";
    public static final String KEY_CARRIER = "carrier";
    public static final String KEY_CHANNEL_TYPE = "channel_type";
    public static final String KEY_CONVERSION_KEY = "conversion_key";
    public static final String KEY_COUNTRY = "country";
    public static final String KEY_HEIGHT = "height";
    public static final String KEY_IS_PORTRAIT = "is_portrait";
    public static final String KEY_LANGUAGE = "language";
    public static final String KEY_LAST_IMP_MINUTE = "last_imp_minute";
    public static final String KEY_LIFE_HOUR = "life_hour";
    public static final String KEY_MODEL = "model";
    public static final String KEY_NETWORKS = "network";
    public static final String KEY_OS = "os";
    public static final String KEY_PACKAGE = "package";
    public static final String KEY_PLATFORM_TYPE = "ptype";
    public static final String KEY_SESSION_COUNT = "session_count";
    public static final String KEY_TOTAL_COUNT = "total_count";
    public static final String KEY_VENDOR = "vendor";
    public static final String KEY_WIDTH = "width";
    public static final String OP_CONTAINS = "contains";
    public static final String OP_EQUAL = "equal";
    public static final String OP_GREATER = "greater";
    public static final String OP_HAS = "has";
    public static final String OP_INFIX = "infix";
    public static final String OP_LESS = "less";
    public static final String OP_NOT_CONTAINS = "not_contains";
    public static final String OP_NOT_EQUAL = "not_equal";
    public static final String OP_NOT_INFIX = "not_infix";
    public static final String OP_NOT_POST_FIX = "not_postfix";
    public static final String OP_NOT_PREFIX = "not_prefix";
    public static final String OP_POSTFIX = "postfix";
    public static final String OP_PREFIX = "prefix";
    public static final String RESET_DAILY = "daily";
    public static final String RESET_MONTHLY = "monthly";
    public static final String RESET_WEEKLY = "weekly";
    public static final String SCHEME_ACTIVITY_COUNTER = "activity_count";
    public static final String SCHEME_ADBRIX = "adbrix";
    public static final String SCHEME_APP = "app";
    public static final String SCHEME_DEVICE = "device";
    public static final String SCHEME_GROUP_COUNT = "group_count";
    public static final String SCHEME_IMPRESSION = "impression";
    public static final String SCHEME_USER = "user";

    public static boolean isMatch(Context context, String op, Object target, Object value, boolean checkPackage) {
        long val;
        long tar;
        long val2;
        long tar2;
        long val3;
        long tar3;
        long val4;
        long tar4;
        long val5;
        long tar5;
        if (target == null || value == null) {
            return false;
        }
        if (checkPackage) {
            try {
                if (op.equals("contains")) {
                    return checkInstalled(context, (String) target);
                }
                if (!op.equals("not_contains")) {
                    return false;
                }
                return !checkInstalled(context, (String) target);
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        } else if (op.equals("equal")) {
            try {
                if (value instanceof String) {
                    val5 = Long.parseLong((String) value);
                } else if (value instanceof Double) {
                    val5 = ((Double) value).longValue();
                } else if (value instanceof Integer) {
                    val5 = ((Integer) value).longValue();
                } else {
                    val5 = ((Long) value).longValue();
                }
                if (target instanceof String) {
                    tar5 = Long.parseLong((String) target);
                } else if (target instanceof Double) {
                    tar5 = ((Double) target).longValue();
                } else if (target instanceof Integer) {
                    tar5 = ((Integer) target).longValue();
                } else {
                    tar5 = ((Long) target).longValue();
                }
                if (val5 == tar5) {
                    return true;
                }
                return false;
            } catch (Exception e2) {
                if (!(value instanceof Comparable) || !(target instanceof Comparable)) {
                    return false;
                }
                return ((Comparable) value).equals((Comparable) target);
            }
        } else if (op.equals("contains")) {
            if (!(value instanceof Collection) || !(target instanceof Collection)) {
                return false;
            }
            return ((Collection) target).containsAll((Collection) value);
        } else if (op.equals("not_equal")) {
            try {
                if (value instanceof String) {
                    val4 = Long.parseLong((String) value);
                } else if (value instanceof Double) {
                    val4 = ((Double) value).longValue();
                } else if (value instanceof Integer) {
                    val4 = ((Integer) value).longValue();
                } else {
                    val4 = ((Long) value).longValue();
                }
                if (target instanceof String) {
                    tar4 = Long.parseLong((String) target);
                } else if (target instanceof Double) {
                    tar4 = ((Double) target).longValue();
                } else if (value instanceof Integer) {
                    tar4 = ((Integer) target).longValue();
                } else {
                    tar4 = ((Long) target).longValue();
                }
                if (val4 != tar4) {
                    return true;
                }
                return false;
            } catch (Exception e3) {
                if (!(value instanceof Comparable) || !(target instanceof Comparable) || ((Comparable) value).equals((Comparable) target)) {
                    return false;
                }
                return true;
            }
        } else if (op.equals("not_contains")) {
            if (!(value instanceof Collection) || !(target instanceof Collection)) {
                return false;
            }
            return ((Collection) target).containsAll((Collection) value);
        } else if (op.equals("prefix")) {
            if (!(value instanceof String) || !(target instanceof String)) {
                return false;
            }
            return ((String) value).toLowerCase().startsWith(((String) target).toLowerCase());
        } else if (op.equals("postfix")) {
            if (!(value instanceof String) || !(target instanceof String)) {
                return false;
            }
            return ((String) value).toLowerCase().endsWith(((String) target).toLowerCase());
        } else if (op.equals("infix")) {
            if (!(value instanceof String) || !(target instanceof String)) {
                return false;
            }
            return ((String) value).toLowerCase().contains(((String) target).toLowerCase());
        } else if (op.equals("not_prefix")) {
            if (!(value instanceof String) || !(target instanceof String) || ((String) value).toLowerCase().contains(((String) target).toLowerCase())) {
                return false;
            }
            return true;
        } else if (op.equals("not_postfix")) {
            if (!(value instanceof String) || !(target instanceof String)) {
                return false;
            }
            return ((String) value).toLowerCase().contains(((String) target).toLowerCase());
        } else if (op.equals("not_infix")) {
            if (!(value instanceof String) || !(target instanceof String)) {
                return false;
            }
            return ((String) value).toLowerCase().contains(((String) target).toLowerCase());
        } else if (op.equals("greater")) {
            try {
                if (value instanceof String) {
                    val3 = Long.parseLong((String) value);
                } else if (value instanceof Double) {
                    val3 = ((Double) value).longValue();
                } else if (value instanceof Integer) {
                    val3 = ((Integer) value).longValue();
                } else {
                    val3 = ((Long) value).longValue();
                }
                if (target instanceof String) {
                    tar3 = Long.parseLong((String) target);
                } else if (target instanceof Double) {
                    tar3 = ((Double) target).longValue();
                } else if (target instanceof Integer) {
                    tar3 = ((Integer) target).longValue();
                } else {
                    tar3 = ((Long) target).longValue();
                }
                if (val3 >= tar3) {
                    return true;
                }
                return false;
            } catch (Exception e4) {
                if (!(value instanceof Comparable) || !(target instanceof Comparable) || ((Comparable) value).compareTo((Comparable) target) < 0) {
                    return false;
                }
                return true;
            }
        } else if (op.equals("less")) {
            try {
                if (value instanceof String) {
                    val2 = Long.parseLong((String) value);
                } else if (value instanceof Double) {
                    val2 = ((Double) value).longValue();
                } else if (value instanceof Integer) {
                    val2 = ((Integer) value).longValue();
                } else {
                    val2 = ((Long) value).longValue();
                }
                if (target instanceof String) {
                    tar2 = Long.parseLong((String) target);
                } else if (target instanceof Double) {
                    tar2 = ((Double) target).longValue();
                } else if (target instanceof Integer) {
                    tar2 = ((Integer) target).longValue();
                } else {
                    tar2 = ((Long) target).longValue();
                }
                if (val2 <= tar2) {
                    return true;
                }
                return false;
            } catch (Exception e5) {
                if (!(value instanceof Comparable) || !(target instanceof Comparable) || ((Comparable) value).compareTo((Comparable) target) > 0) {
                    return false;
                }
                return true;
            }
        } else if (!op.equals("has")) {
            return false;
        } else {
            try {
                if (value instanceof String) {
                    val = Long.parseLong((String) value);
                } else if (value instanceof Double) {
                    val = ((Double) value).longValue();
                } else if (value instanceof Integer) {
                    val = ((Integer) value).longValue();
                } else {
                    val = ((Long) value).longValue();
                }
                if (target instanceof String) {
                    tar = Long.parseLong((String) target);
                } else if (target instanceof Double) {
                    tar = ((Double) target).longValue();
                } else if (value instanceof Integer) {
                    tar = ((Integer) target).longValue();
                } else {
                    tar = ((Long) target).longValue();
                }
                if ((val & tar) == val) {
                    return true;
                }
                return false;
            } catch (Exception e6) {
                if (!(value instanceof Comparable) || !(target instanceof Comparable) || ((Comparable) value).equals((Comparable) target)) {
                    return false;
                }
                return true;
            }
        }
    }

    public static Object getUserValue(Context context, RequestParameter parameter, int scheduleType, String targetStorageKey, String scheme, String key) {
        try {
            if (scheme.equals("device")) {
                if (key.equals("vendor")) {
                    return parameter.getMarketPlace();
                }
                if (key.equals("model")) {
                    return parameter.getModel();
                }
                if (key.equals("network")) {
                    return parameter.getCustomNetworkInfo(context);
                }
                if (key.equals("os")) {
                    return "a_" + VERSION.RELEASE;
                }
                if (key.equals("ptype")) {
                    return "android";
                }
                if (key.equals("width")) {
                    return Integer.valueOf(((WindowManager) context.getSystemService("window")).getDefaultDisplay().getWidth());
                }
                if (key.equals("height")) {
                    return Integer.valueOf(((WindowManager) context.getSystemService("window")).getDefaultDisplay().getHeight());
                }
                if (key.equals("is_portrait")) {
                    return Integer.valueOf(context.getResources().getConfiguration().orientation);
                }
                return null;
            } else if (scheme.equals("user")) {
                if (key.equals("carrier")) {
                    return ((TelephonyManager) context.getSystemService("phone")).getNetworkOperatorName();
                }
                if (key.equals("country")) {
                    return Locale.getDefault().getCountry();
                }
                if (key.equals("language")) {
                    return Locale.getDefault().getLanguage();
                }
                return null;
            } else if (scheme.equals("adbrix")) {
                if (key.equals("life_hour")) {
                    return Long.valueOf(parameter.calculateLifeHour());
                }
                if (key.equals("app_launch_count")) {
                    return Long.valueOf(parameter.getappLaunchCount());
                }
                if (key.equals("channel_type")) {
                    return Integer.valueOf(parameter.getChannelType());
                }
                if (key.equals("conversion_key")) {
                    return parameter.getConversionCache();
                }
                return null;
            } else if (scheme.equals("impression")) {
                AbstractCPEImpressionDAO dao = CPEImpressionDAOFactory.getImpressionDAO(scheme, key, scheduleType);
                if (dao == null) {
                    return Integer.valueOf(0);
                }
                try {
                    if (key.equals("total_count")) {
                        return Integer.valueOf(Integer.parseInt(dao.getImpressionData(context, scheduleType, targetStorageKey, key)) + 1);
                    }
                    if (key.equals("session_count")) {
                        return Integer.valueOf(Integer.parseInt(dao.getImpressionData(context, scheduleType, targetStorageKey, key)) + 1);
                    }
                    if (!key.equals("last_imp_minute")) {
                        return Integer.valueOf(0);
                    }
                    return new StringBuilder(String.valueOf((new Date().getTime() - Long.parseLong(dao.getImpressionData(context, scheduleType, targetStorageKey, key))) / 60000)).toString();
                } catch (Exception e) {
                    return Integer.valueOf(0);
                }
            } else if (scheme.equals("activity_count")) {
                String[] splittedKey = key.split("::--::");
                if (splittedKey.length != 2) {
                    return null;
                }
                String group = splittedKey[0];
                String activity = splittedKey[1];
                if (group == null && activity == null) {
                    return null;
                }
                return Integer.valueOf(CounterDAOForAllActivity.getDAO(context).getCountInAllActivityByGroupAndActivity(group, activity));
            } else if (scheme.equals("group_count")) {
                return Integer.valueOf(CounterDAOForAllActivity.getDAO(context).getCountInAllActivityByGroup(key));
            } else {
                if (!scheme.equals("app")) {
                    return null;
                }
                try {
                    if (key.equals("package")) {
                        return "";
                    }
                    return null;
                } catch (Exception e2) {
                    return null;
                }
            }
        } catch (Exception e3) {
            e3.printStackTrace();
            return null;
        }
    }

    public static boolean checkInstalled(Context context, String scheme) {
        try {
            return context.getPackageManager().getApplicationInfo(scheme, 0) != null;
        } catch (NameNotFoundException e) {
            return false;
        }
    }
}