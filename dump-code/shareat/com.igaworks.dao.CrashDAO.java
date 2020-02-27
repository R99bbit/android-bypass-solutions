package com.igaworks.dao;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import java.util.ArrayList;
import java.util.List;

public class CrashDAO {
    public static final String CRASH_SP_NAME = "igaw_crashes";

    public static SharedPreferences getCrashSP(Context context) {
        return context.getSharedPreferences(CRASH_SP_NAME, 0);
    }

    public static Editor getEditor(Context context) {
        return getCrashSP(context).edit();
    }

    public static void updateCrash(Context context, String key, String value) {
        IgawLogger.Logging(context, IgawConstant.QA_TAG, String.format("updateCrash : %s = %s ", new Object[]{key, value}), 3);
        Editor edt = getEditor(context);
        edt.putString(key, value);
        edt.commit();
    }

    public static List<String> getCrashes(Context context) {
        try {
            ArrayList arrayList = new ArrayList(getCrashSP(context).getAll().values());
            try {
                return arrayList;
            } catch (Exception e) {
                e.printStackTrace();
                return arrayList;
            }
        } catch (Exception e2) {
            e2.printStackTrace();
            try {
            } catch (Exception e3) {
                e3.printStackTrace();
            }
            return null;
        } finally {
            try {
                Editor edt = getCrashSP(context).edit();
                edt.clear();
                edt.commit();
            } catch (Exception e4) {
                e4.printStackTrace();
            }
        }
    }
}