package com.nuvent.shareat.model.friend;

import java.util.ArrayList;

public class FriendResultModel {
    private int cnt_follow_00;
    private int cnt_follow_05;
    private int cnt_follow_10;
    private int cnt_follow_20;
    private int cnt_follow_i;
    private String result;
    private ArrayList<FriendModel> result_list;
    private int total_cnt;

    public int getCnt_follow_i() {
        return this.cnt_follow_i;
    }

    public void setCnt_follow_i(int cnt_follow_i2) {
        this.cnt_follow_i = cnt_follow_i2;
    }

    public int getCnt_follow_20() {
        return this.cnt_follow_20;
    }

    public void setCnt_follow_20(int cnt_follow_202) {
        this.cnt_follow_20 = cnt_follow_202;
    }

    public int getCnt_follow_05() {
        return this.cnt_follow_05;
    }

    public void setCnt_follow_05(int cnt_follow_052) {
        this.cnt_follow_05 = cnt_follow_052;
    }

    public int getCnt_follow_10() {
        return this.cnt_follow_10;
    }

    public void setCnt_follow_10(int cnt_follow_102) {
        this.cnt_follow_10 = cnt_follow_102;
    }

    public int getCnt_follow_00() {
        return this.cnt_follow_00;
    }

    public void setCnt_follow_00(int cnt_follow_002) {
        this.cnt_follow_00 = cnt_follow_002;
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

    public ArrayList<FriendModel> getResult_list() {
        return this.result_list;
    }

    public void setResult_list(ArrayList<FriendModel> result_list2) {
        this.result_list = result_list2;
    }
}