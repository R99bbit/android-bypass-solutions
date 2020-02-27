package com.nuvent.shareat.model.store;

import com.nuvent.shareat.model.BaseResultModel;
import java.util.ArrayList;

public class CategoryResultModel extends BaseResultModel {
    public ArrayList<CategoryModel> result_list;

    public ArrayList<CategoryModel> getResult_list() {
        if (this.result_list == null) {
            this.result_list = new ArrayList<>();
        }
        return this.result_list;
    }
}