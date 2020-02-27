package com.nuvent.shareat.model;

import java.util.ArrayList;

public class CouponModel {
    private String result;
    private String result_code;
    private ArrayList<CouponDetailModel> result_list;

    public String getResult_code() {
        return this.result_code;
    }

    public void setResult_code(String result_code2) {
        this.result_code = result_code2;
    }

    public String getResult() {
        return this.result;
    }

    public void setResult(String result2) {
        this.result = result2;
    }

    public ArrayList<CouponDetailModel> getResult_list() {
        return this.result_list;
    }

    public void setResult_list(ArrayList<CouponDetailModel> result_list2) {
        this.result_list = result_list2;
    }
}