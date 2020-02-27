package com.nuvent.shareat.model.store;

import com.nuvent.shareat.model.BaseResultModel;
import java.util.ArrayList;

public class StoreInstaResultModel extends BaseResultModel {
    public String chk_review;
    public ArrayList<StoreInstaModel> result_list = new ArrayList<>();
    public String total_cnt;

    public ArrayList<StoreInstaModel> getResult_list() {
        return this.result_list;
    }

    public boolean isChkReview() {
        if ("Y".equals(this.chk_review)) {
            return true;
        }
        return false;
    }

    public String getTotal_cnt() {
        return this.total_cnt;
    }
}