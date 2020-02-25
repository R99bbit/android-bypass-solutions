package com.embrain.panelbigdata;

import android.app.Application;
import android.content.Context;

public class EmBigdataApplication extends Application {
    private static Context mContext;

    public static Context getContext() {
        return mContext;
    }

    protected static void setContext(Context context) {
        mContext = context;
    }
}