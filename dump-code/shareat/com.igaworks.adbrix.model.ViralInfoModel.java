package com.igaworks.adbrix.model;

public class ViralInfoModel {
    private String imageURL;
    private boolean isTest;
    private String itemName;
    private String itemQuantity;
    private boolean result;
    private int resultCode;
    private String resultMsg;

    public ViralInfoModel() {
    }

    public ViralInfoModel(boolean isTest2, boolean result2, int resultCode2, String resultMsg2, String imageURL2, String itemName2) {
        this.isTest = isTest2;
        this.result = result2;
        this.resultCode = resultCode2;
        this.resultMsg = resultMsg2;
        this.imageURL = imageURL2;
        this.itemName = itemName2;
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

    public String getImageURL() {
        return this.imageURL;
    }

    public void setImageURL(String imageURL2) {
        this.imageURL = imageURL2;
    }

    public String getItemName() {
        return this.itemName;
    }

    public void setItemName(String itemName2) {
        this.itemName = itemName2;
    }

    public String getItemQuantity() {
        return this.itemQuantity;
    }

    public void setItemQuantity(String itemQuantity2) {
        this.itemQuantity = itemQuantity2;
    }
}