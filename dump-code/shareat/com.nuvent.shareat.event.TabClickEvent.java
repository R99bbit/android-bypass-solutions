package com.nuvent.shareat.event;

public class TabClickEvent {
    private int mType;

    public TabClickEvent(int type) {
        this.mType = type;
    }

    public int getmType() {
        return this.mType;
    }

    public void setmType(int mType2) {
        this.mType = mType2;
    }
}