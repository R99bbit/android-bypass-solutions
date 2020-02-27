package com.nuvent.shareat.model.store;

import com.nuvent.shareat.model.BaseResultModel;
import java.util.ArrayList;

public class StoreReviewResultModel extends BaseResultModel {
    public String chk_review;
    public ArrayList<ReviewModel> result_list = new ArrayList<>();
    public String total_cnt;

    public ArrayList<ReviewModel> getResult_list() {
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