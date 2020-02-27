package com.ning.http.client;

public class StringPart implements Part {
    private final String charset;
    private final String name;
    private final String value;

    public StringPart(String name2, String value2, String charset2) {
        this.name = name2;
        this.value = value2;
        this.charset = charset2;
    }

    public StringPart(String name2, String value2) {
        this.name = name2;
        this.value = value2;
        this.charset = "UTF-8";
    }

    public String getName() {
        return this.name;
    }

    public String getValue() {
        return this.value;
    }

    public String getCharset() {
        return this.charset;
    }
}