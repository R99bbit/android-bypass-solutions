package com.nuvent.shareat.model.store;

import java.io.Serializable;
import java.util.ArrayList;

public class StoreBlogModel extends StoreListModel implements Serializable {
    private String linkUrl;
    private String postDate;
    private String postType;
    private ArrayList<String> reviewImgList;
    private int rowNum;
    private String snippet;
    private String title;

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

    public String getSnippet() {
        return this.snippet;
    }

    public void setSnippet(String snippet2) {
        this.snippet = snippet2;
    }

    public String getLinkUrl() {
        return this.linkUrl;
    }

    public void setLinkUrl(String linkUrl2) {
        this.linkUrl = linkUrl2;
    }

    public String getPostType() {
        return this.postType;
    }

    public void setPostType(String postType2) {
        this.postType = postType2;
    }

    public String getPostDate() {
        return this.postDate;
    }

    public void setPostDate(String postDate2) {
        this.postDate = postDate2;
    }

    public ArrayList<String> getReviewImgList() {
        return this.reviewImgList;
    }

    public void setReviewImgList(ArrayList<String> reviewImgList2) {
        this.reviewImgList = reviewImgList2;
    }
}