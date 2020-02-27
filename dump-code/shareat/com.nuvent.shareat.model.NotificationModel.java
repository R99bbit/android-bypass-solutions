package com.nuvent.shareat.model;

import java.io.Serializable;

public class NotificationModel implements Serializable {
    private String notice_id;
    private String use_yn;

    public String getNotice_id() {
        return this.notice_id;
    }

    public String getUse_yn() {
        return this.use_yn;
    }

    public void setNotice_id(String notice_id2) {
        this.notice_id = notice_id2;
    }

    public void setUse_yn(String use_yn2) {
        this.use_yn = use_yn2;
    }
}