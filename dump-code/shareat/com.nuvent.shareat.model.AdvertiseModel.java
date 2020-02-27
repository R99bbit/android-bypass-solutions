package com.nuvent.shareat.model;

import java.util.ArrayList;

public class AdvertiseModel {
    private String result;
    private String result_code;
    private ArrayList<AdvertiseDetailModel> result_list;
    private int total_cnt;

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

    public int getTotal_cnt() {
        return this.total_cnt;
    }

    public void setTotal_cnt(int total_cnt2) {
        this.total_cnt = total_cnt2;
    }

    public ArrayList<AdvertiseDetailModel> getResult_list() {
        return this.result_list;
    }

    public void setResult_list(ArrayList<AdvertiseDetailModel> result_list2) {
        this.result_list = result_list2;
    }
}