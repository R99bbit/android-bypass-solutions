package com.igaworks.interfaces;

import android.content.Context;

public interface ICommonLiveOpsCallbackListener {
    void OnCommonSetUsn(Context context, String str);

    void onEndSession(Context context);
}