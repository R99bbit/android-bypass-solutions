package com.nuvent.shareat.model.delivery;

import com.nuvent.shareat.model.JsonConvertable;

public class DeliveryInfoModel extends JsonConvertable {
    private String address;
    private String address_rest;
    private String default_address;
    private String method;
    private String order_name;
    private String order_phone;
    private String receive_name;
    private String receive_phone;
    private String use_safe_phone;
    private String zip_code;

    public String getAddress() {
        return this.address;
    }

    public void setAddress(String address2) {
        this.address = address2;
    }

    public String getAddress_rest() {
        return this.address_rest;
    }

    public void setAddress_rest(String address_rest2) {
        this.address_rest = address_rest2;
    }

    public String getReceive_name() {
        return this.receive_name;
    }

    public void setReceive_name(String receive_name2) {
        this.receive_name = receive_name2;
    }

    public String getReceive_phone() {
        return this.receive_phone;
    }

    public void setReceive_phone(String receive_phone2) {
        this.receive_phone = receive_phone2;
    }

    public String getOrder_name() {
        return this.order_name;
    }

    public void setOrder_name(String order_name2) {
        this.order_name = order_name2;
    }

    public String getOrder_phone() {
        return this.order_phone;
    }

    public void setOrder_phone(String order_phone2) {
        this.order_phone = order_phone2;
    }

    public String getZip_code() {
        return this.zip_code;
    }

    public void setZip_code(String zip_code2) {
        this.zip_code = zip_code2;
    }

    public String getDefault_address() {
        return this.default_address;
    }

    public void setDefault_address(String default_address2) {
        this.default_address = default_address2;
    }

    public String getUse_safe_phone() {
        return this.use_safe_phone;
    }

    public void setUse_safe_phone(String use_safe_phone2) {
        this.use_safe_phone = use_safe_phone2;
    }

    public String getMethod() {
        return this.method;
    }

    public void setMethod(String method2) {
        this.method = method2;
    }
}