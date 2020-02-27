package com.nuvent.shareat.model.search;

import java.io.Serializable;

public class SearchUserModel implements Serializable {
    private String userImg;
    private String userName;
    private String userSno;

    public String getUserName() {
        return this.userName;
    }

    public void setUserName(String userName2) {
        this.userName = userName2;
    }

    public String getUserSno() {
        return this.userSno;
    }

    public void setUserSno(String userSno2) {
        this.userSno = userSno2;
    }

    public String getUserImg() {
        return this.userImg;
    }

    public void setUserImg(String userImg2) {
        this.userImg = userImg2;
    }
}