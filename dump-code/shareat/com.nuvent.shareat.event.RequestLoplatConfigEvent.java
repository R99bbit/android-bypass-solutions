package com.nuvent.shareat.event;

public class RequestLoplatConfigEvent {
    private String externalBrand;

    public RequestLoplatConfigEvent(String externalBrand2) {
        this.externalBrand = externalBrand2;
    }

    public String getExternalBrand() {
        return this.externalBrand;
    }
}