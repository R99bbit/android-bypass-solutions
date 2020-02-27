package com.ning.http.multipart;

public abstract class PartBase extends Part {
    private String charSet;
    private String contentId;
    private String contentType;
    private String name;
    private String transferEncoding;

    public PartBase(String name2, String contentType2, String charSet2, String transferEncoding2, String contentId2) {
        if (name2 == null) {
            throw new IllegalArgumentException("Name must not be null");
        }
        this.name = name2;
        this.contentType = contentType2;
        this.charSet = charSet2;
        this.transferEncoding = transferEncoding2;
        this.contentId = contentId2;
    }

    public String getName() {
        return this.name;
    }

    public String getContentType() {
        return this.contentType;
    }

    public String getCharSet() {
        return this.charSet;
    }

    public String getTransferEncoding() {
        return this.transferEncoding;
    }

    public void setCharSet(String charSet2) {
        this.charSet = charSet2;
    }

    public void setContentType(String contentType2) {
        this.contentType = contentType2;
    }

    public void setName(String name2) {
        if (name2 == null) {
            throw new IllegalArgumentException("Name must not be null");
        }
        this.name = name2;
    }

    public void setTransferEncoding(String transferEncoding2) {
        this.transferEncoding = transferEncoding2;
    }

    public String getContentId() {
        return this.contentId;
    }

    public void setContentId(String contentId2) {
        this.contentId = contentId2;
    }
}