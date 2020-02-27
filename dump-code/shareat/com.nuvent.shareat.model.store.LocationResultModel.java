package com.nuvent.shareat.model.store;

import com.nuvent.shareat.model.BaseResultModel;
import java.util.ArrayList;

public class LocationResultModel extends BaseResultModel {
    public ArrayList<LocationModel> result_list;

    public ArrayList<LocationModel> getResult_list() {
        if (this.result_list == null) {
            this.result_list = new ArrayList<>();
        }
        return this.result_list;
    }
}