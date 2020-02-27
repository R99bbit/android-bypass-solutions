package com.nuvent.shareat.model.store;

import com.nuvent.shareat.model.BaseResultModel;

public class StoreDetailResultModel extends BaseResultModel {
    public StoreDetailModel store_detail;
    public int total_cnt;

    public int getTotal_cnt() {
        return this.total_cnt;
    }

    public void setTotal_cnt(int total_cnt2) {
        this.total_cnt = total_cnt2;
    }

    public StoreDetailModel getStore_detail() {
        if (this.store_detail == null) {
            this.store_detail = new StoreDetailModel();
        }
        return this.store_detail;
    }

    public void setStore_detail(StoreDetailModel store_detail2) {
        this.store_detail = store_detail2;
    }
}