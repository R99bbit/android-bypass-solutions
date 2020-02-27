package com.nuvent.shareat.event;

public class PaySuccessEvent {
    public boolean isDeliveryCardViewFinish = false;

    public PaySuccessEvent(boolean isDeliveryCardViewFinish2) {
        this.isDeliveryCardViewFinish = isDeliveryCardViewFinish2;
    }

    public PaySuccessEvent() {
    }
}