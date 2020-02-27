package com.nuvent.shareat.model;

import java.util.ArrayList;

public class PaydisResultModel extends BaseResultModel {
    private ArrayList<PaydisModel> result_list = new ArrayList<>();

    public ArrayList<PaydisModel> getResult_list() {
        return this.result_list;
    }
}