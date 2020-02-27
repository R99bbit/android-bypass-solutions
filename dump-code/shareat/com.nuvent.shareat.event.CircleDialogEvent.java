package com.nuvent.shareat.event;

public class CircleDialogEvent {
    boolean isShow;

    public CircleDialogEvent(boolean isShow2) {
        this.isShow = isShow2;
    }

    public boolean isShow() {
        return this.isShow;
    }

    public void setIsShow(boolean isShow2) {
        this.isShow = isShow2;
    }
}