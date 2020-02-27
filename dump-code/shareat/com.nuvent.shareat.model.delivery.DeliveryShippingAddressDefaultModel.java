package com.nuvent.shareat.model.delivery;

import com.nuvent.shareat.model.JsonConvertable;

public class DeliveryShippingAddressDefaultModel extends JsonConvertable {
    private String address;
    private String addressRest;
    private String receiveName;
    private String receivePhone;
    private String zipCode;

    public String getAddress() {
        return this.address;
    }

    public void setAddress(String address2) {
        this.address = address2;
    }

    public String getAddressRest() {
        return this.addressRest;
    }

    public void setAddressRest(String addressRest2) {
        this.addressRest = addressRest2;
    }

    public String getReceiveName() {
        return this.receiveName;
    }

    public void setReceiveName(String receiveName2) {
        this.receiveName = receiveName2;
    }

    public String getReceivePhone() {
        return this.receivePhone;
    }

    public void setReceivePhone(String receivePhone2) {
        this.receivePhone = receivePhone2;
    }

    public String getZipCode() {
        return this.zipCode;
    }

    public void setZipCode(String zipCode2) {
        this.zipCode = zipCode2;
    }
}