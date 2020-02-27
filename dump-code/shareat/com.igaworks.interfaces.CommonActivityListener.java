package com.igaworks.interfaces;

import android.content.Context;
import com.igaworks.core.RequestParameter;

public interface CommonActivityListener {
    void onActivityCalled(Context context, String str, String str2, RequestParameter requestParameter);

    void onGetReferralResponse(Context context, String str);

    void onStartSession(Context context, RequestParameter requestParameter, boolean z);
}