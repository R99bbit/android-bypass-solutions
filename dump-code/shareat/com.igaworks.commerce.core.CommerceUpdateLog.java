package com.igaworks.commerce.core;

import android.util.Log;
import com.igaworks.core.IgawConstant;

public class CommerceUpdateLog {
    public static final String COMMERCE_VERSION = "1.2.3";

    public static void updateVersion() {
        Log.d(IgawConstant.QA_TAG, "commerce version : 1.2.3");
    }
}