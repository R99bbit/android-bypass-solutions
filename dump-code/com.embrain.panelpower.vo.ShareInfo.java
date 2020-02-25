package com.embrain.panelpower.vo;

public class ShareInfo {
    public static final String TYPE_EVENT = "event";
    public static final String TYPE_LOCATION = "location";
    public static final String TYPE_RECOMMAND = "recommend";
    public static final String TYPE_SURVEY = "survey";
    public String contents;
    public String eventId;
    public String imageId;
    public String title;
    public String type;

    public ShareInfo(String str, String str2, String str3, String str4, String str5) {
        this.type = str;
        this.title = str2;
        this.contents = str3;
        this.imageId = str4;
        this.eventId = str5;
    }
}