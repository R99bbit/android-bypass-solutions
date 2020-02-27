package com.nuvent.shareat.model;

import java.io.Serializable;

public class HashModel implements Serializable {
    private String tagCount;
    private String tagName;

    public String getTagName() {
        return this.tagName;
    }

    public void setTagName(String tagName2) {
        this.tagName = tagName2;
    }

    public String getTagCount() {
        return this.tagCount;
    }

    public void setTagCount(String tagCount2) {
        this.tagCount = tagCount2;
    }
}