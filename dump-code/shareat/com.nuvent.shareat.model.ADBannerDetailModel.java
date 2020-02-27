package com.nuvent.shareat.model;

public class ADBannerDetailModel extends BaseResultModel {
    private String ad_id;
    private String img_url;
    private String scheme_url;
    private String sub_title;

    public String getAd_id() {
        return this.ad_id;
    }

    public void setAd_id(String ad_id2) {
        this.ad_id = ad_id2;
    }

    public String getScheme_url() {
        return this.scheme_url;
    }

    public void setScheme_url(String scheme_url2) {
        this.scheme_url = scheme_url2;
    }

    public String getImg_url() {
        return this.img_url;
    }

    public void setImg_url(String img_url2) {
        this.img_url = img_url2;
    }

    public String getSub_title() {
        return this.sub_title;
    }

    public void setSub_title(String sub_title2) {
        this.sub_title = sub_title2;
    }
}