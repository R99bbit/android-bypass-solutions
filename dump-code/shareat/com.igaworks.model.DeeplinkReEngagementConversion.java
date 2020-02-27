package com.igaworks.model;

public class DeeplinkReEngagementConversion {
    private int conversionKey;
    private String deeplink_info;
    private int isDirty;
    private int key = -1;
    private int retryCnt;

    public DeeplinkReEngagementConversion(int key2, int conversionKey2, String deeplink_info2, int retryCnt2, int isDirty2) {
        this.key = key2;
        this.conversionKey = conversionKey2;
        this.deeplink_info = deeplink_info2;
        this.retryCnt = retryCnt2;
        this.isDirty = isDirty2;
    }

    public int getKey() {
        return this.key;
    }

    public void setKey(int key2) {
        this.key = key2;
    }

    public int getConversionKey() {
        return this.conversionKey;
    }

    public void setConversionKey(int conversionKey2) {
        this.conversionKey = conversionKey2;
    }

    public String getDeeplink_info() {
        return this.deeplink_info;
    }

    public void setDeeplink_info(String deeplink_info2) {
        this.deeplink_info = deeplink_info2;
    }

    public int getRetryCnt() {
        return this.retryCnt;
    }

    public void setRetryCnt(int retryCnt2) {
        this.retryCnt = retryCnt2;
    }

    public int getIsDirty() {
        return this.isDirty;
    }

    public void setIsDirty(int isDirty2) {
        this.isDirty = isDirty2;
    }
}