package com.nuvent.shareat.model;

import java.util.ArrayList;

public class StoreCouponResultModel extends BaseResultModel {
    private ArrayList<CouponDetailModel> result_list = new ArrayList<>();

    public ArrayList<CouponDetailModel> getResult_list() {
        return this.result_list;
    }
}