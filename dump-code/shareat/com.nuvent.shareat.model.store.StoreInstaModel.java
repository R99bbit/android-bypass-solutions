package com.nuvent.shareat.model.store;

import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Date;

public class StoreInstaModel extends StoreListModel implements Serializable {
    public static final int HOUR = 24;
    public static final String MESSAGE_CARD_TIME_FORMAT = "yyyy.MM.dd";
    public static final int MIN = 60;
    public static final int SEC = 60;
    private String contentsImgUrl;
    private String createdTime;
    private String instaSno;
    private String likesCount;
    private String linkUrl;
    private String partnerName1;
    private String postId;
    private int rowNum;
    private String title;
    private String userFullName;
    private String userId;
    private String userName;
    private String userProfileImgUrl;

    public String getPartnerName1() {
        return this.partnerName1;
    }

    public String getLikesCount() {
        return this.likesCount;
    }

    public int getRowNum() {
        return this.rowNum;
    }

    public void setRowNum(int rowNum2) {
        this.rowNum = rowNum2;
    }

    public String getTitle() {
        return this.title;
    }

    public void setTitle(String title2) {
        this.title = title2;
    }

    public String getInstaSno() {
        return this.instaSno;
    }

    public void setInstaSno(String instaSno2) {
        this.instaSno = instaSno2;
    }

    public String getPostId() {
        return this.postId;
    }

    public void setPostId(String postId2) {
        this.postId = postId2;
    }

    public String getCreatedTime() {
        return this.createdTime;
    }

    public void setCreatedTime(String createdTime2) {
        this.createdTime = createdTime2;
    }

    public String getContentsImgUrl() {
        return this.contentsImgUrl;
    }

    public void setContentsImgUrl(String contentsImgUrl2) {
        this.contentsImgUrl = contentsImgUrl2;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String userId2) {
        this.userId = userId2;
    }

    public String getUserName() {
        return this.userName;
    }

    public void setUserName(String userName2) {
        this.userName = userName2;
    }

    public String getUserFullName() {
        return this.userFullName;
    }

    public void setUserFullName(String userFullName2) {
        this.userFullName = userFullName2;
    }

    public String getUserProfileImgUrl() {
        return this.userProfileImgUrl;
    }

    public void setUserProfileImgUrl(String userProfileImgUrl2) {
        this.userProfileImgUrl = userProfileImgUrl2;
    }

    public String getLinkUrl() {
        return this.linkUrl;
    }

    public void setLinkUrl(String linkUrl2) {
        this.linkUrl = linkUrl2;
    }

    public String getTermEvent() {
        long diffTime = (System.currentTimeMillis() - new Date(Long.valueOf(this.createdTime).longValue() * 1000).getTime()) / 1000;
        if (diffTime < 60) {
            return "\uc9c0\uae08\ub9c9";
        }
        long diffTime2 = diffTime / 60;
        if (diffTime2 < 60) {
            return diffTime2 + "\ubd84\uc804";
        }
        long diffTime3 = diffTime2 / 60;
        if (diffTime3 < 24) {
            return diffTime3 + "\uc2dc\uac04\uc804";
        }
        return getDateFormat(MESSAGE_CARD_TIME_FORMAT, Long.valueOf(this.createdTime).longValue() * 1000);
    }

    private String getDateFormat(String str, long time) {
        return new SimpleDateFormat(str).format(new Date(time));
    }
}