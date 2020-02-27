package com.igaworks.commerce.model;

public class CommerceV2EventItem {
    private String eventJson;
    private int isDirty;
    private int key;
    private int retryCnt;

    public int getIsDirty() {
        return this.isDirty;
    }

    public void setIsDirty(int isDirty2) {
        this.isDirty = isDirty2;
    }

    public CommerceV2EventItem() {
    }

    public CommerceV2EventItem(int key2, String pJson, int retryCnt2) {
        this.key = key2;
        this.eventJson = pJson;
        this.retryCnt = retryCnt2;
        this.isDirty = 0;
    }

    public String getJson() {
        return this.eventJson;
    }

    public void setJson(String pJson) {
        this.eventJson = pJson;
    }

    public int getKey() {
        return this.key;
    }

    public void setKey(int key2) {
        this.key = key2;
    }

    public int getRetryCnt() {
        return this.retryCnt;
    }

    public void setRetryCnt(int retryCnt2) {
        this.retryCnt = retryCnt2;
    }
}