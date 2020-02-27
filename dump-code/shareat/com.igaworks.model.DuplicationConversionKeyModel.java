package com.igaworks.model;

public class DuplicationConversionKeyModel {
    private long completeTime;
    private String conversion;

    public DuplicationConversionKeyModel(long completeTime2, String conversion2) {
        this.completeTime = completeTime2;
        this.conversion = conversion2;
    }

    public long getCompleteTime() {
        return this.completeTime;
    }

    public void setCompleteTime(long completeTime2) {
        this.completeTime = completeTime2;
    }

    public String getConversion() {
        return this.conversion;
    }

    public void setConversion(String conversion2) {
        this.conversion = conversion2;
    }
}