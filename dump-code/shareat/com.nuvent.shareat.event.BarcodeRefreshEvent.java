package com.nuvent.shareat.event;

public class BarcodeRefreshEvent {
    private String mExpireDate;
    private String mMethod;

    public BarcodeRefreshEvent(String method, String mExpireDate2) {
        this.mMethod = method;
        this.mExpireDate = mExpireDate2;
    }

    public String getMethod() {
        return this.mMethod;
    }

    public String getExpireDate() {
        return this.mExpireDate;
    }
}