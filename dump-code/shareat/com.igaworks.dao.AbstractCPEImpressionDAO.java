package com.igaworks.dao;

import android.content.Context;

public abstract class AbstractCPEImpressionDAO {
    protected static final String KEY_DELIMETER = "::--::";
    public static final String PARENT_KEY_GROUP = "::--::;";
    protected static final String PERSIST_SP_NAME_FOR_AD_SPACE = "persist_ad_space_counter";
    protected static final String PERSIST_SP_NAME_FOR_ENGAGEMENT = "persist_cpe_counter";
    protected static final String PERSIST_SP_NAME_FOR_PROMOTION = "persist_promotion_counter";
    protected static final String SESSION_SP_NAME_FOR_AD_SPACE = "session_ad_space_counter";
    protected static final String SESSION_SP_NAME_FOR_ENGAGEMENT = "session_cpe_counter";
    protected static final String SESSION_SP_NAME_FOR_PROMOTION = "session_promotion_counter";

    public abstract void clearImpressionData(Context context);

    public abstract String getImpressionData(Context context, int i, String str, String str2);

    public abstract void increaseImpressionData(Context context, int i, String str, String str2);

    public abstract void removeImpressionData(Context context, int i, String str, String str2);

    public abstract void setImpressionData(Context context, int i, String str, String str2, String str3);
}