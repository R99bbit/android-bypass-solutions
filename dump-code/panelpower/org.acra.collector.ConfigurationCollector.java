package org.acra.collector;

import android.content.Context;
import android.content.res.Configuration;
import android.util.Log;
import android.util.SparseArray;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import org.acra.ACRA;

public final class ConfigurationCollector {
    private static final String FIELD_MCC = "mcc";
    private static final String FIELD_MNC = "mnc";
    private static final String FIELD_SCREENLAYOUT = "screenLayout";
    private static final String FIELD_UIMODE = "uiMode";
    private static final String PREFIX_HARDKEYBOARDHIDDEN = "HARDKEYBOARDHIDDEN_";
    private static final String PREFIX_KEYBOARD = "KEYBOARD_";
    private static final String PREFIX_KEYBOARDHIDDEN = "KEYBOARDHIDDEN_";
    private static final String PREFIX_NAVIGATION = "NAVIGATION_";
    private static final String PREFIX_NAVIGATIONHIDDEN = "NAVIGATIONHIDDEN_";
    private static final String PREFIX_ORIENTATION = "ORIENTATION_";
    private static final String PREFIX_SCREENLAYOUT = "SCREENLAYOUT_";
    private static final String PREFIX_TOUCHSCREEN = "TOUCHSCREEN_";
    private static final String PREFIX_UI_MODE = "UI_MODE_";
    private static final String SUFFIX_MASK = "_MASK";
    private static SparseArray<String> mHardKeyboardHiddenValues = new SparseArray<>();
    private static SparseArray<String> mKeyboardHiddenValues = new SparseArray<>();
    private static SparseArray<String> mKeyboardValues = new SparseArray<>();
    private static SparseArray<String> mNavigationHiddenValues = new SparseArray<>();
    private static SparseArray<String> mNavigationValues = new SparseArray<>();
    private static SparseArray<String> mOrientationValues = new SparseArray<>();
    private static SparseArray<String> mScreenLayoutValues = new SparseArray<>();
    private static SparseArray<String> mTouchScreenValues = new SparseArray<>();
    private static SparseArray<String> mUiModeValues = new SparseArray<>();
    private static final HashMap<String, SparseArray<String>> mValueArrays = new HashMap<>();

    static {
        Field[] fieldArr;
        mValueArrays.put(PREFIX_HARDKEYBOARDHIDDEN, mHardKeyboardHiddenValues);
        mValueArrays.put(PREFIX_KEYBOARD, mKeyboardValues);
        mValueArrays.put(PREFIX_KEYBOARDHIDDEN, mKeyboardHiddenValues);
        mValueArrays.put(PREFIX_NAVIGATION, mNavigationValues);
        mValueArrays.put(PREFIX_NAVIGATIONHIDDEN, mNavigationHiddenValues);
        mValueArrays.put(PREFIX_ORIENTATION, mOrientationValues);
        mValueArrays.put(PREFIX_SCREENLAYOUT, mScreenLayoutValues);
        mValueArrays.put(PREFIX_TOUCHSCREEN, mTouchScreenValues);
        mValueArrays.put(PREFIX_UI_MODE, mUiModeValues);
        Field[] fields = Configuration.class.getFields();
        int length = fields.length;
        int i = 0;
        while (i < length) {
            Field field = fields[i];
            if (!Modifier.isStatic(field.getModifiers()) || !Modifier.isFinal(field.getModifiers())) {
                fieldArr = fields;
            } else {
                String name = field.getName();
                try {
                    fieldArr = fields;
                    if (name.startsWith(PREFIX_HARDKEYBOARDHIDDEN)) {
                        try {
                            mHardKeyboardHiddenValues.put(field.getInt(null), name);
                        } catch (IllegalArgumentException e) {
                            e = e;
                            Log.w(ACRA.LOG_TAG, "Error while inspecting device configuration: ", e);
                            i++;
                            fields = fieldArr;
                        } catch (IllegalAccessException e2) {
                            e = e2;
                            Log.w(ACRA.LOG_TAG, "Error while inspecting device configuration: ", e);
                            i++;
                            fields = fieldArr;
                        }
                    } else if (name.startsWith(PREFIX_KEYBOARD)) {
                        mKeyboardValues.put(field.getInt(null), name);
                    } else if (name.startsWith(PREFIX_KEYBOARDHIDDEN)) {
                        mKeyboardHiddenValues.put(field.getInt(null), name);
                    } else if (name.startsWith(PREFIX_NAVIGATION)) {
                        mNavigationValues.put(field.getInt(null), name);
                    } else if (name.startsWith(PREFIX_NAVIGATIONHIDDEN)) {
                        mNavigationHiddenValues.put(field.getInt(null), name);
                    } else if (name.startsWith(PREFIX_ORIENTATION)) {
                        mOrientationValues.put(field.getInt(null), name);
                    } else if (name.startsWith(PREFIX_SCREENLAYOUT)) {
                        mScreenLayoutValues.put(field.getInt(null), name);
                    } else if (name.startsWith(PREFIX_TOUCHSCREEN)) {
                        mTouchScreenValues.put(field.getInt(null), name);
                    } else if (name.startsWith(PREFIX_UI_MODE)) {
                        mUiModeValues.put(field.getInt(null), name);
                    }
                } catch (IllegalArgumentException e3) {
                    e = e3;
                    fieldArr = fields;
                    Log.w(ACRA.LOG_TAG, "Error while inspecting device configuration: ", e);
                    i++;
                    fields = fieldArr;
                } catch (IllegalAccessException e4) {
                    e = e4;
                    fieldArr = fields;
                    Log.w(ACRA.LOG_TAG, "Error while inspecting device configuration: ", e);
                    i++;
                    fields = fieldArr;
                }
            }
            i++;
            fields = fieldArr;
        }
    }

    public static String toString(Configuration configuration) {
        Field[] fields;
        StringBuilder sb = new StringBuilder();
        for (Field field : configuration.getClass().getFields()) {
            try {
                if (!Modifier.isStatic(field.getModifiers())) {
                    sb.append(field.getName());
                    sb.append('=');
                    if (field.getType().equals(Integer.TYPE)) {
                        sb.append(getFieldValueName(configuration, field));
                    } else if (field.get(configuration) != null) {
                        sb.append(field.get(configuration).toString());
                    }
                    sb.append(10);
                }
            } catch (IllegalArgumentException e) {
                Log.e(ACRA.LOG_TAG, "Error while inspecting device configuration: ", e);
            } catch (IllegalAccessException e2) {
                Log.e(ACRA.LOG_TAG, "Error while inspecting device configuration: ", e2);
            }
        }
        return sb.toString();
    }

    private static String getFieldValueName(Configuration configuration, Field field) throws IllegalAccessException {
        String name = field.getName();
        if (name.equals(FIELD_MCC) || name.equals(FIELD_MNC)) {
            return Integer.toString(field.getInt(configuration));
        }
        if (name.equals(FIELD_UIMODE)) {
            return activeFlags(mValueArrays.get(PREFIX_UI_MODE), field.getInt(configuration));
        }
        if (name.equals(FIELD_SCREENLAYOUT)) {
            return activeFlags(mValueArrays.get(PREFIX_SCREENLAYOUT), field.getInt(configuration));
        }
        HashMap<String, SparseArray<String>> hashMap = mValueArrays;
        StringBuilder sb = new StringBuilder();
        sb.append(name.toUpperCase());
        sb.append('_');
        SparseArray sparseArray = hashMap.get(sb.toString());
        if (sparseArray == null) {
            return Integer.toString(field.getInt(configuration));
        }
        String str = (String) sparseArray.get(field.getInt(configuration));
        return str == null ? Integer.toString(field.getInt(configuration)) : str;
    }

    private static String activeFlags(SparseArray<String> sparseArray, int i) {
        StringBuilder sb = new StringBuilder();
        for (int i2 = 0; i2 < sparseArray.size(); i2++) {
            int keyAt = sparseArray.keyAt(i2);
            if (sparseArray.get(keyAt).endsWith(SUFFIX_MASK)) {
                int i3 = keyAt & i;
                if (i3 > 0) {
                    if (sb.length() > 0) {
                        sb.append('+');
                    }
                    sb.append(sparseArray.get(i3));
                }
            }
        }
        return sb.toString();
    }

    public static String collectConfiguration(Context context) {
        try {
            return toString(context.getResources().getConfiguration());
        } catch (RuntimeException e) {
            String str = ACRA.LOG_TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("Couldn't retrieve CrashConfiguration for : ");
            sb.append(context.getPackageName());
            Log.w(str, sb.toString(), e);
            return "Couldn't retrieve crash config";
        }
    }
}