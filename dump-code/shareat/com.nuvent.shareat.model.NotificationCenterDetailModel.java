package com.nuvent.shareat.model;

public class NotificationCenterDetailModel extends BaseResultModel {
    private String check_read;
    private String feed_sno;
    private String link_url;
    private String message;
    private String profile;
    private String push_sno;
    private String read_date;
    private String send_date;
    private String target_link;
    private String title;
    private String type;

    public void setProfile(String profile2) {
        this.profile = profile2;
    }

    public String getTitle() {
        return this.title;
    }

    public void setTitle(String title2) {
        this.title = title2;
    }

    public String getMessage() {
        return this.message;
    }

    public void setMessage(String message2) {
        this.message = message2;
    }

    public String getType() {
        return this.type;
    }

    public void setType(String type2) {
        this.type = type2;
    }

    public String getPush_sno() {
        return this.push_sno;
    }

    public void setPush_sno(String push_sno2) {
        this.push_sno = push_sno2;
    }

    public String getCheck_read() {
        return this.check_read;
    }

    public void setCheck_read(String check_read2) {
        this.check_read = check_read2;
    }

    public String getSend_date() {
        return this.send_date;
    }

    public void setSend_date(String send_date2) {
        this.send_date = send_date2;
    }

    public String getLink_url() {
        return this.link_url;
    }

    public void setLink_url(String link_url2) {
        this.link_url = link_url2;
    }

    public String getFeed_sno() {
        return this.feed_sno;
    }

    public void setFeed_sno(String feed_sno2) {
        this.feed_sno = feed_sno2;
    }

    public String getRead_date() {
        return this.read_date;
    }

    public void setRead_date(String read_date2) {
        this.read_date = read_date2;
    }

    public String getProfile() {
        return this.profile;
    }

    public String getTarget_link() {
        return this.target_link;
    }

    public void setTarget_link(String target_link2) {
        this.target_link = target_link2;
    }
}