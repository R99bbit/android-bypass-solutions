package com.nuvent.shareat.event;

public class PayingEvent {
    public boolean isDeliveryCardView = false;
    private boolean isPaying;

    public PayingEvent(boolean isPaying2) {
        this.isPaying = isPaying2;
    }

    public PayingEvent(boolean isPaying2, boolean deliveryCardView) {
        this.isPaying = isPaying2;
        this.isDeliveryCardView = deliveryCardView;
    }

    public boolean isPaying() {
        return this.isPaying;
    }
}