package com.nuvent.shareat.model.store;

import com.nuvent.shareat.model.BaseResultModel;
import java.util.ArrayList;

public class StoreAllImageResultModel extends BaseResultModel {
    public ArrayList<StoreAllImageModel> result_list;
    public int total_cnt;

    public ArrayList<StoreAllImageModel> getResult_list() {
        return this.result_list;
    }

    public int getTotal_cnt() {
        return this.total_cnt;
    }
}