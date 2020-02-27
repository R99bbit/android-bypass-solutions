package com.nuvent.shareat.event;

import com.nuvent.shareat.model.AdvertiseModel;

public class AdvertiseEvent {
    private AdvertiseType advertiseType;
    private AdvertiseModel mAdvertiseModel = null;

    public enum AdvertiseType {
        GATEWAY,
        MAIN
    }

    public AdvertiseType getAdvertiseType() {
        return this.advertiseType;
    }

    public void setAdvertiseType(AdvertiseType advertiseType2) {
        this.advertiseType = advertiseType2;
    }

    public AdvertiseEvent(AdvertiseModel am) {
        this.mAdvertiseModel = am;
        setAdvertiseType(AdvertiseType.MAIN);
    }

    public AdvertiseModel getAdvertiseModel() {
        return this.mAdvertiseModel;
    }
}