package com.nuvent.shareat.model.delivery;

import com.nuvent.shareat.model.JsonConvertable;

public class DeliveryPossibleAreaDetailModel extends JsonConvertable {
    private String deliveryPrice;
    private String localName;

    public String getLocalName() {
        return this.localName;
    }

    public void setLocalName(String localName2) {
        this.localName = localName2;
    }

    public String getDeliveryPrice() {
        return this.deliveryPrice;
    }

    public void setDeliveryPrice(String deliveryPrice2) {
        this.deliveryPrice = deliveryPrice2;
    }
}