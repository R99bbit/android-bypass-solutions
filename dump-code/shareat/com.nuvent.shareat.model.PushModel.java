package com.nuvent.shareat.model;

import java.io.Serializable;

public class PushModel implements Serializable {
    public String customScheme;
    public String linkUrl;
    private String message;
    public String partner_sno;
    public String push_sno;
    public int type = 1;

    public String getPush_sno() {
        return this.push_sno;
    }

    public void setPush_sno(String push_sno2) {
        this.push_sno = push_sno2;
    }

    public String getMessage() {
        return this.message;
    }

    public void setMessage(String message2) {
        this.message = message2;
    }

    public String getCustomScheme() {
        return this.customScheme;
    }

    public void setCustomScheme(String customScheme2) {
        this.customScheme = customScheme2;
    }

    public int getType() {
        return this.type;
    }

    public void setType(int type2) {
        this.type = type2;
    }

    public String getPartner_sno() {
        return this.partner_sno;
    }

    public void setPartner_sno(String partner_sno2) {
        this.partner_sno = partner_sno2;
    }

    public String getLinkUrl() {
        return this.linkUrl;
    }

    public void setLinkUrl(String linkUrl2) {
        this.linkUrl = linkUrl2;
    }
}