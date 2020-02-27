package com.nuvent.shareat.event;

public class CardViewStatusEvent {
    public boolean isDeliveryCardView = false;

    public CardViewStatusEvent(boolean isDeliveryCardView2) {
        this.isDeliveryCardView = isDeliveryCardView2;
    }

    public CardViewStatusEvent() {
    }
}