package com.nuvent.shareat.model;

public class BannerModel {
    private String banner_kind;
    private String image_url;
    private String link_url;
    private String title;

    public void setTitle(String title2) {
        this.title = title2;
    }

    public void setImage_url(String image_url2) {
        this.image_url = image_url2;
    }

    public void setLink_url(String link_url2) {
        this.link_url = link_url2;
    }

    public void setBanner_kind(String banner_kind2) {
        this.banner_kind = banner_kind2;
    }

    public String getTitle() {
        return this.title;
    }

    public String getImage_url() {
        return this.image_url;
    }

    public String getLink_url() {
        return this.link_url;
    }

    public String getBanner_kind() {
        return this.banner_kind;
    }
}