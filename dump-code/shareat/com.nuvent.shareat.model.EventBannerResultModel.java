package com.nuvent.shareat.model;

import java.util.ArrayList;

public class EventBannerResultModel extends BaseResultModel {
    private ArrayList<BannerModel> result_list = new ArrayList<>();

    public ArrayList<BannerModel> getResult_list() {
        return this.result_list;
    }
}