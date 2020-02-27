package com.nuvent.shareat.model.user;

import java.io.Serializable;

public class UserModel implements Serializable {
    public String email;
    public String join_gubun;
    public String login_yn;
    public String noti_yn;
    public String open_yn;
    public String push_key;
    public boolean pwConfirmed;
    public String pwd_gubun;
    public String pwd_yn;
    public String user_id;
    public String user_img;
    public String user_name;
    public String user_phone;
    public String user_view_name;

    public boolean isEnablePassword() {
        return this.login_yn != null && this.login_yn.equals("Y");
    }

    public boolean enableOpen() {
        return this.open_yn != null && "0Y".contains(this.open_yn);
    }

    public String getUserName() {
        return this.user_name;
    }

    public void setUser_name(String user_name2) {
        this.user_name = user_name2;
    }

    public String getPwd_gubun() {
        return this.pwd_gubun;
    }

    public void setPwd_gubun(String pwd_gubun2) {
        this.pwd_gubun = pwd_gubun2;
    }

    public String getEmail() {
        return this.email;
    }

    public void setEmail(String email2) {
        this.email = email2;
    }

    public String getUserImg() {
        return this.user_img;
    }

    public void setUser_img(String user_img2) {
        this.user_img = user_img2;
    }

    public String getUser_phone() {
        return this.user_phone;
    }

    public void setUser_phone(String user_phone2) {
        this.user_phone = user_phone2;
    }

    public String getUser_view_name() {
        return this.user_view_name;
    }

    public void setUser_view_name(String user_view_name2) {
        this.user_view_name = user_view_name2;
    }

    public String getUser_id() {
        return this.user_id;
    }

    public void setUser_id(String user_id2) {
        this.user_id = user_id2;
    }

    public String getJoin_gubun() {
        return this.join_gubun;
    }

    public void setJoin_gubun(String join_gubun2) {
        this.join_gubun = join_gubun2;
    }

    public String getNoti_yn() {
        return this.noti_yn;
    }

    public void setNoti_yn(String noti_yn2) {
        this.noti_yn = noti_yn2;
    }

    public String getPwd_yn() {
        return this.pwd_yn;
    }

    public void setPwd_yn(String pwd_yn2) {
        this.pwd_yn = pwd_yn2;
    }

    public String getOpen_yn() {
        return this.open_yn;
    }

    public void setOpen_yn(String open_yn2) {
        this.open_yn = open_yn2;
    }

    public String getLogin_yn() {
        return this.login_yn;
    }

    public void setLogin_yn(String login_yn2) {
        this.login_yn = login_yn2;
    }

    public String getPush_key() {
        return this.push_key;
    }

    public void setPush_key(String push_key2) {
        this.push_key = push_key2;
    }

    public boolean isPwConfirmed() {
        return this.pwConfirmed;
    }

    public void setPwConfirmed(boolean pwConfirmed2) {
        this.pwConfirmed = pwConfirmed2;
    }
}