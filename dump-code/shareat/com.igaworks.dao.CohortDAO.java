package com.igaworks.dao;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;

public class CohortDAO {
    public static final String COHORT_SP_NAME = "cohorts";
    public static String cohort1;
    public static String cohort2;
    public static String cohort3;

    public static SharedPreferences getCohortSP(Context context) {
        return context.getSharedPreferences(COHORT_SP_NAME, 0);
    }

    public static Editor getEditor(Context context) {
        return getCohortSP(context).edit();
    }

    public static void updateCohort(Context context, String key, String value) {
        IgawLogger.Logging(context, IgawConstant.QA_TAG, String.format("updateCohort : %s = %s ", new Object[]{key, value}), 3);
        Editor edt = getEditor(context);
        edt.putString(key, value);
        edt.commit();
    }

    public static String getCohort(Context context, String key) {
        if (key.equals(RequestParameter.COHORT_1_NAME) && cohort1 != null && cohort1.length() > 0) {
            return cohort1;
        }
        if (key.equals(RequestParameter.COHORT_2_NAME) && cohort2 != null && cohort2.length() > 0) {
            return cohort2;
        }
        if (key.equals(RequestParameter.COHORT_3_NAME) && cohort3 != null && cohort3.length() > 0) {
            return cohort3;
        }
        String cohort = getCohortSP(context).getString(key, null);
        if (key.equals(RequestParameter.COHORT_1_NAME)) {
            cohort1 = cohort;
            return cohort;
        } else if (key.equals(RequestParameter.COHORT_2_NAME)) {
            cohort2 = cohort;
            return cohort;
        } else if (!key.equals(RequestParameter.COHORT_3_NAME)) {
            return cohort;
        } else {
            cohort3 = cohort;
            return cohort;
        }
    }
}