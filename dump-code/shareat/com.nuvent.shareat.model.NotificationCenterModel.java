package com.nuvent.shareat.model;

import java.util.ArrayList;

public class NotificationCenterModel extends JsonConvertable {
    private String result;
    private String result_code;
    private ArrayList<NotificationCenterDetailModel> result_list;
    private int total_cnt;

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

    public ArrayList<NotificationCenterDetailModel> getResult_list() {
        return this.result_list;
    }

    public void setResult_list(ArrayList<NotificationCenterDetailModel> result_list2) {
        this.result_list = result_list2;
    }
}