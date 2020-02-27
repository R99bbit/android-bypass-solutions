package com.nuvent.shareat.model.user;

import java.io.Serializable;

public class UserProfileModel implements Serializable {
    private String cnt_follow;
    private String cnt_following;
    private String cnt_friend;
    private String cnt_pay;
    private String follow_status;
    private String follow_status_text;
    private String open_yn;
    private String target_user_img;
    private String target_user_name;
    private String target_user_sno;

    public boolean isOpen() {
        return this.open_yn != null && "0Y".contains(this.open_yn);
    }

    public String getCnt_follow() {
        return this.cnt_follow;
    }

    public void setCnt_follow(String cnt_follow2) {
        this.cnt_follow = cnt_follow2;
    }

    public String getCnt_pay() {
        return this.cnt_pay;
    }

    public void setCnt_pay(String cnt_pay2) {
        this.cnt_pay = cnt_pay2;
    }

    public String getTarget_user_name() {
        return this.target_user_name;
    }

    public void setTarget_user_name(String target_user_name2) {
        this.target_user_name = target_user_name2;
    }

    public String getOpen_yn() {
        return this.open_yn;
    }

    public void setOpen_yn(String open_yn2) {
        this.open_yn = open_yn2;
    }

    public String getFollow_status() {
        return this.follow_status;
    }

    public void setFollow_status(String follow_status2) {
        this.follow_status = follow_status2;
    }

    public String getCnt_friend() {
        return this.cnt_friend;
    }

    public void setCnt_friend(String cnt_friend2) {
        this.cnt_friend = cnt_friend2;
    }

    public String getFollow_status_text() {
        return this.follow_status_text;
    }

    public void setFollow_status_text(String follow_status_text2) {
        this.follow_status_text = follow_status_text2;
    }

    public String getTarget_user_sno() {
        return this.target_user_sno;
    }

    public void setTarget_user_sno(String target_user_sno2) {
        this.target_user_sno = target_user_sno2;
    }

    public String getCnt_following() {
        return this.cnt_following;
    }

    public void setCnt_following(String cnt_following2) {
        this.cnt_following = cnt_following2;
    }

    public String getTarget_user_img() {
        return this.target_user_img;
    }

    public void setTarget_user_img(String target_user_img2) {
        this.target_user_img = target_user_img2;
    }
}