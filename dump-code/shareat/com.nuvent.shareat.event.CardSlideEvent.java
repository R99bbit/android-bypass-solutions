package com.nuvent.shareat.event;

public class CardSlideEvent {
    private boolean isOpen;

    public CardSlideEvent(boolean isOpen2) {
        this.isOpen = isOpen2;
    }

    public boolean isOpen() {
        return this.isOpen;
    }
}