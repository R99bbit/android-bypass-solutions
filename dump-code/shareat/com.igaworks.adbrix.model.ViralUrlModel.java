package com.igaworks.adbrix.model;

public class ViralUrlModel {
    private boolean isTest;
    private boolean result;
    private int resultCode;
    private String resultMsg;
    private String trackingURL;

    public ViralUrlModel() {
    }

    public ViralUrlModel(boolean isTest2, boolean result2, int resultCode2, String resultMsg2, String trackingURL2) {
        this.isTest = isTest2;
        this.result = result2;
        this.resultCode = resultCode2;
        this.resultMsg = resultMsg2;
        this.trackingURL = trackingURL2;
    }

    public boolean isTest() {
        return this.isTest;
    }

    public void setTest(boolean isTest2) {
        this.isTest = isTest2;
    }

    public boolean isResult() {
        return this.result;
    }

    public void setResult(boolean result2) {
        this.result = result2;
    }

    public int getResultCode() {
        return this.resultCode;
    }

    public void setResultCode(int resultCode2) {
        this.resultCode = resultCode2;
    }

    public String getResultMsg() {
        return this.resultMsg;
    }

    public void setResultMsg(String resultMsg2) {
        this.resultMsg = resultMsg2;
    }

    public String getTrackingURL() {
        return this.trackingURL;
    }

    public void setTrackingURL(String trackingURL2) {
        this.trackingURL = trackingURL2;
    }
}