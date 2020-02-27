package com.igaworks.model;

public class DeeplinkConversionItem {
    private String commerceClickID;
    private int conversionKey;
    private int isDirty;
    private int key;
    private String linkParams;
    private int retryCnt;

    public DeeplinkConversionItem() {
    }

    public DeeplinkConversionItem(int key2, int conversionKey2, String commerceClickID2, String linkParams2, int retryCnt2, int isDirty2) {
        this.key = key2;
        this.conversionKey = conversionKey2;
        this.commerceClickID = commerceClickID2;
        this.linkParams = linkParams2;
        this.retryCnt = retryCnt2;
        this.isDirty = isDirty2;
    }

    public int getRetryCnt() {
        return this.retryCnt;
    }

    public void setRetryCnt(int retryCnt2) {
        this.retryCnt = retryCnt2;
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

    public String getCommerceClickID() {
        return this.commerceClickID;
    }

    public void setCommerceClickID(String commerceClickID2) {
        this.commerceClickID = commerceClickID2;
    }

    public String getLinkParams() {
        return this.linkParams;
    }

    public void setLinkParams(String linkParams2) {
        this.linkParams = linkParams2;
    }

    public int getIsDirty() {
        return this.isDirty;
    }
}