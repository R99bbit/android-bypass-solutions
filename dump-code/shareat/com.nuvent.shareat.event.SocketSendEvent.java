package com.nuvent.shareat.event;

import java.util.Map;

public class SocketSendEvent {
    public static final int REQUEST_TYPE_CALCEL = 3;
    public static final int REQUEST_TYPE_INIT = 1;
    public static final int REQUEST_TYPE_SEND = 2;
    private Map<String, String> mDatas;
    private String mMethodStr;
    private int mType;

    public SocketSendEvent(int type, String mMethodStr2, Map<String, String> mDatas2) {
        this.mType = type;
        this.mMethodStr = mMethodStr2;
        this.mDatas = mDatas2;
    }

    public int getType() {
        return this.mType;
    }

    public String getMethodStr() {
        return this.mMethodStr;
    }

    public Map<String, String> getDatas() {
        return this.mDatas;
    }
}