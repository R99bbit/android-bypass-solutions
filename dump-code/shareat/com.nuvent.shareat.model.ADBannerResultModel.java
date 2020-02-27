package com.nuvent.shareat.model;

import java.util.ArrayList;

public class ADBannerResultModel extends BaseResultModel {
    private ArrayList<ADBannerDetailModel> result_list = new ArrayList<>();
    private String total_cnt;

    public ArrayList<ADBannerDetailModel> getResult_list() {
        return this.result_list;
    }

    public String getTotal_cnt() {
        return this.total_cnt;
    }

    public void setTotal_cnt(String total_cnt2) {
        this.total_cnt = total_cnt2;
    }
}