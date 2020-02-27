package com.igaworks.interfaces;

import android.app.Activity;
import android.content.Context;

public interface CommonInterface {
    public static final String AD_SPACE_GROUP = "adspace";
    public static final String CREATED_AT_DATE_FORMAT = "yyyyMMddHHmmss";
    public static final String CREATED_AT_DATE_FORMAT2 = "yyyy-MM-dd HH:mm:ss";

    void addIntentReceiver(String str);

    void clearIntentReceiver();

    @Deprecated
    void custom(String str);

    @Deprecated
    void custom(String str, String str2);

    void deeplinkConversion(Activity activity, boolean z);

    void endSession();

    @Deprecated
    void error(String str, String str2);

    void onReceiveReferral(Context context);

    void onReceiveReferral(Context context, String str);

    void removeIntentReceiver(String str);

    void setAge(int i);

    void setClientRewardEventListener(IgawRewardItemEventListener igawRewardItemEventListener);

    void setDeferredLinkListener(Context context, DeferredLinkListener deferredLinkListener);

    void setGender(int i);

    void setReferralUrlForFacebook(Context context, String str);

    void setUserId(String str);

    void startApplicationForInternalUse(Context context);

    void startSession(Context context);

    @Deprecated
    void viral(String str);

    @Deprecated
    void viral(String str, String str2);
}