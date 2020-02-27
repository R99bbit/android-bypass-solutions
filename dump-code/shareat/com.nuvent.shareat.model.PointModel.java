package com.nuvent.shareat.model;

import java.util.ArrayList;

public class PointModel {
    private String result;
    private String result_code;
    private String result_expire_point;
    private ArrayList<PointDetailModel> result_list;
    private String result_point;

    public String getResult() {
        return this.result;
    }

    public void setResult(String result2) {
        this.result = result2;
    }

    public String getResult_code() {
        return this.result_code;
    }

    public void setResult_code(String result_code2) {
        this.result_code = result_code2;
    }

    public String getResult_point() {
        return this.result_point;
    }

    public void setResult_point(String result_point2) {
        this.result_point = result_point2;
    }

    public String getResult_expire_point() {
        return this.result_expire_point;
    }

    public void setResult_expire_point(String result_expire_point2) {
        this.result_expire_point = result_expire_point2;
    }

    public ArrayList<PointDetailModel> getResult_list() {
        return this.result_list;
    }

    public void setResult_list(ArrayList<PointDetailModel> result_list2) {
        this.result_list = result_list2;
    }
}