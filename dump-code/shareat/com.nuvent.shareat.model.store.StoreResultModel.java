package com.nuvent.shareat.model.store;

import com.nuvent.shareat.model.BaseResultModel;
import java.util.ArrayList;

public class StoreResultModel extends BaseResultModel {
    private String head_period_text;
    public ArrayList<StoreModel> result_list;
    public String total_cnt;

    public String getHead_period_text() {
        return this.head_period_text;
    }

    public String getTotalCount() {
        return this.total_cnt;
    }

    public void setTotalCount(String total_cnt2) {
        this.total_cnt = total_cnt2;
    }

    public ArrayList<StoreModel> getResultList() {
        if (this.result_list == null) {
            this.result_list = new ArrayList<>();
        }
        return this.result_list;
    }

    public void setResultList(ArrayList<StoreModel> result_list2) {
        this.result_list = result_list2;
    }
}