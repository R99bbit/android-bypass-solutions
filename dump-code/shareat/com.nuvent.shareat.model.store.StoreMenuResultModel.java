package com.nuvent.shareat.model.store;

import com.nuvent.shareat.model.BaseResultModel;
import java.util.ArrayList;

public class StoreMenuResultModel extends BaseResultModel {
    public String recent_cnt_pay;
    private ArrayList<ChartModel> result_chart = new ArrayList<>();
    private String result_date;
    private ArrayList<StoreMenuModel> result_list = new ArrayList<>();
    public String result_set;
    public int total_cnt;
    public int total_cnt_pay;

    public String getResult_date() {
        return this.result_date;
    }

    public int getTotal_cnt_pay() {
        return this.total_cnt_pay;
    }

    public String getRecent_cnt_pay() {
        return this.recent_cnt_pay;
    }

    public void setChartList(ArrayList<ChartModel> list) {
        this.result_chart = list;
    }

    public ArrayList<ChartModel> getChartList() {
        return this.result_chart;
    }

    public String getResult_set() {
        return this.result_set;
    }

    public int getTotal_cnt() {
        return this.total_cnt;
    }

    public ArrayList<StoreMenuModel> getResult_list() {
        return this.result_list;
    }
}