package com.nuvent.shareat.model;

public class VersionModel extends BaseResultModel {
    public String url;
    public String version;

    public String getVersion() {
        return this.version;
    }

    public void setVersion(String version2) {
        this.version = version2;
    }

    public String getUrl() {
        return this.url;
    }

    public void setUrl(String url2) {
        this.url = url2;
    }
}