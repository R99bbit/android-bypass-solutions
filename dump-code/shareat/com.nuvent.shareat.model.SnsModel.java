package com.nuvent.shareat.model;

import java.io.Serializable;

public class SnsModel implements Serializable {
    private String accessToken;
    private String avatarImageUrl;
    private String gender;
    private String snsId;
    private String userEmail;
    private String userName;

    public String getSNSID() {
        return this.snsId;
    }

    public void setSNSID(String snsId2) {
        this.snsId = snsId2;
    }

    public String getUserName() {
        return this.userName;
    }

    public void setUserName(String userName2) {
        this.userName = userName2;
    }

    public String getUserEmail() {
        return this.userEmail;
    }

    public void setUserEmail(String userEmail2) {
        this.userEmail = userEmail2;
    }

    public String getGender() {
        return this.gender;
    }

    public void setGender(String gender2) {
        this.gender = gender2;
    }

    public String getAccessToken() {
        return this.accessToken;
    }

    public void setAccessToken(String accessToken2) {
        this.accessToken = accessToken2;
    }

    public String getAvatarImageUrl() {
        return this.avatarImageUrl;
    }

    public void setAvatarImageUrl(String avatarImageUrl2) {
        this.avatarImageUrl = avatarImageUrl2;
    }
}