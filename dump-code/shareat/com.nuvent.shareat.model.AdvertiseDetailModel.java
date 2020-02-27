package com.nuvent.shareat.model;

public class AdvertiseDetailModel extends BaseResultModel {
    private String image_path;
    private int menu_sno;
    private String scheme_url;
    private String title;

    public String getImage_path() {
        return this.image_path;
    }

    public String getScheme_url() {
        return this.scheme_url;
    }

    public int getMenu_sno() {
        return this.menu_sno;
    }

    public String getTitle() {
        return this.title;
    }
}