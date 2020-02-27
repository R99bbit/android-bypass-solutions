package com.nuvent.shareat.model;

import java.io.Serializable;

public class ReviewTagModel implements Serializable {
    private String code_id;
    private String code_name;

    public void setCode_id(String code_id2) {
        this.code_id = code_id2;
    }

    public void setCode_name(String code_name2) {
        this.code_name = code_name2;
    }

    public String getCode_id() {
        return this.code_id;
    }

    public String getCode_name() {
        return this.code_name;
    }
}