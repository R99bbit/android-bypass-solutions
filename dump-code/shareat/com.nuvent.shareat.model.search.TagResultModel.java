package com.nuvent.shareat.model.search;

import com.nuvent.shareat.model.BaseResultModel;
import java.util.ArrayList;

public class TagResultModel extends BaseResultModel {
    public ArrayList<TagModel> result_list = new ArrayList<>();
    public int total_cnt;

    public ArrayList<TagModel> getResult_list() {
        return this.result_list;
    }

    public int getTotal_cnt() {
        return this.total_cnt;
    }
}