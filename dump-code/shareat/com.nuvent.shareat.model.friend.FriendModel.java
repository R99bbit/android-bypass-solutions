package com.nuvent.shareat.model.friend;

public class FriendModel {
    private String follow_status;
    private String follow_status_text;
    private String friend_img;
    private String friend_name;
    private String friend_sno;
    private String last_index;
    private String name;
    private int totalCount;
    private String user_img;
    private String user_name;
    private String user_phone;
    private String user_sno;

    public String getName() {
        return this.name;
    }

    public void setName(String name2) {
        this.name = name2;
    }

    public int getTotalCount() {
        return this.totalCount;
    }

    public void setTotalCount(int totalCount2) {
        this.totalCount = totalCount2;
    }

    public String getUser_name() {
        return this.user_name;
    }

    public void setUser_name(String user_name2) {
        this.user_name = user_name2;
    }

    public String getUser_sno() {
        return this.user_sno;
    }

    public void setUser_sno(String user_sno2) {
        this.user_sno = user_sno2;
    }

    public String getUser_img() {
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

    public String getFriend_sno() {
        return this.friend_sno;
    }

    public void setFriend_sno(String friend_sno2) {
        this.friend_sno = friend_sno2;
    }

    public String getFriend_name() {
        return this.friend_name;
    }

    public void setFriend_name(String friend_name2) {
        this.friend_name = friend_name2;
    }

    public String getFollow_status() {
        return this.follow_status;
    }

    public void setFollow_status(String follow_status2) {
        this.follow_status = follow_status2;
    }

    public String getFriend_img() {
        return this.friend_img;
    }

    public void setFriend_img(String friend_img2) {
        this.friend_img = friend_img2;
    }

    public String getFollow_status_text() {
        return this.follow_status_text;
    }

    public void setFollow_status_text(String follow_status_text2) {
        this.follow_status_text = follow_status_text2;
    }

    public String getLast_index() {
        return this.last_index;
    }

    public void setLast_index(String last_index2) {
        this.last_index = last_index2;
    }
}