package com.nuvent.shareat.model.search;

import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.HashModel;
import java.util.ArrayList;

public class SearchTagResultModel extends BaseResultModel {
    public ArrayList<HashModel> result_list;
    public String total_cnt;

    public String getTotalCount() {
        return this.total_cnt;
    }

    public void setTotalCount(String total_cnt2) {
        this.total_cnt = total_cnt2;
    }

    public ArrayList<HashModel> getResultList() {
        if (this.result_list == null) {
            this.result_list = new ArrayList<>();
        }
        return this.result_list;
    }

    public void setResultList(ArrayList<HashModel> result_list2) {
        this.result_list = result_list2;
    }
}