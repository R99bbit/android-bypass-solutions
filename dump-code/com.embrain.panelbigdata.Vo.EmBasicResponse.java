package com.embrain.panelbigdata.Vo;

import androidx.core.os.EnvironmentCompat;

public class EmBasicResponse {
    public static final int CODE_ERROR_NETWORK_ERROR = 499;
    public static final int CODE_ERROR_PARSE_ERROR = 110;
    public static final int CODE_ERROR_UNKNOWN = 199;
    public static final int CODE_SUCCESS = 200;
    public int mCode;
    public String mMesssage;

    private String setMessage(int i) {
        return i != 110 ? i != 200 ? i != 499 ? "unknown error" : "network error" : "Success" : "parse error";
    }

    public EmBasicResponse(int i) {
        this(i, EnvironmentCompat.MEDIA_UNKNOWN);
    }

    public EmBasicResponse(int i, String str) {
        this.mCode = i;
        this.mMesssage = setMessage(i);
    }
}