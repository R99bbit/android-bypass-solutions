package com.nuvent.shareat.event;

public class PostGnbOptionEvent {
    private boolean mChangeListType;

    public PostGnbOptionEvent() {
        this.mChangeListType = false;
    }

    public PostGnbOptionEvent(boolean changeListType) {
        this.mChangeListType = changeListType;
    }

    public boolean isChangeListType() {
        return this.mChangeListType;
    }
}