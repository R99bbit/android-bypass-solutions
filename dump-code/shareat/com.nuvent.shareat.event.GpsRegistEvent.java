package com.nuvent.shareat.event;

public class GpsRegistEvent {
    private Object mData;

    public GpsRegistEvent(Object mData2) {
        this.mData = mData2;
    }

    public Object getData() {
        return this.mData;
    }
}