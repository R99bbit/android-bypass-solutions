package com.nuvent.shareat.event;

public class ImageClickEvent {
    private int index;

    public ImageClickEvent(int index2) {
        this.index = index2;
    }

    public int getIndex() {
        return this.index;
    }
}