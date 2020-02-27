package com.nuvent.shareat.model;

public class RecommendLookAroundDetailModel extends BaseResultModel {
    private String image_path;
    private String scheme_url;
    private String sub_title;
    private String title;

    public String getImage_path() {
        return this.image_path;
    }

    public String getScheme_url() {
        return this.scheme_url;
    }

    public String getSub_title() {
        return this.sub_title;
    }

    public String getTitle() {
        return this.title;
    }
}