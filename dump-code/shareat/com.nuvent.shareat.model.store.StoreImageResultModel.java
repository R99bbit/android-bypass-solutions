package com.nuvent.shareat.model.store;

import com.nuvent.shareat.model.BaseResultModel;
import java.util.ArrayList;

public class StoreImageResultModel extends BaseResultModel {
    public ArrayList<StoreImageModel> result_list = new ArrayList<>();

    public ArrayList<StoreImageModel> getResult_list() {
        return this.result_list;
    }
}