package com.igaworks.adbrix.model;

public class RetryCompleteConversion {
    private int conversionKey;
    private int retryCount;

    public RetryCompleteConversion() {
    }

    public RetryCompleteConversion(int conversionKey2, int retryCount2) {
        this.conversionKey = conversionKey2;
        this.retryCount = retryCount2;
    }

    public int getConversionKey() {
        return this.conversionKey;
    }

    public void setConversionKey(int conversionKey2) {
        this.conversionKey = conversionKey2;
    }

    public int getRetryCount() {
        return this.retryCount;
    }

    public void setRetryCount(int retryCount2) {
        this.retryCount = retryCount2;
    }
}