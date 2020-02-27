package com.nuvent.shareat.model;

public class AddressModel extends JsonConvertable {
    private String id;
    private String user_name;
    private String user_phone;

    public String getId() {
        return this.id;
    }

    public void setId(String id2) {
        this.id = id2;
    }

    public String getPhonenum() {
        return this.user_phone;
    }

    public void setPhonenum(String phonenum) {
        this.user_phone = phonenum;
    }

    public String getName() {
        return this.user_name;
    }

    public void setName(String name) {
        this.user_name = name;
    }
}