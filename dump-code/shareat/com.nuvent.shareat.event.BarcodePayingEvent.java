package com.nuvent.shareat.event;

public class BarcodePayingEvent {
    private String mBarcode;
    private String mExpireDate;
    private String mImageUrl;

    public BarcodePayingEvent(String mBarcode2, String mExpireDate2, String imageUrl) {
        this.mBarcode = mBarcode2;
        this.mExpireDate = mExpireDate2;
        this.mImageUrl = imageUrl;
    }

    public String getExpireDate() {
        return this.mExpireDate;
    }

    public String getBarcode() {
        return this.mBarcode;
    }

    public String getImageUrl() {
        return this.mImageUrl;
    }
}