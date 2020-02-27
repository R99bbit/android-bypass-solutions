package com.nuvent.shareat.model.delivery;

import com.nuvent.shareat.model.BaseResultModel;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Map;

public class DeliveryPossibleAreaModel extends BaseResultModel implements Serializable {
    private ArrayList<Map<String, ArrayList<DeliveryPossibleAreaDetailModel>>> result_list = new ArrayList<>();

    public ArrayList<Map<String, ArrayList<DeliveryPossibleAreaDetailModel>>> getResult_list() {
        return this.result_list;
    }

    public void setResult_list(ArrayList<Map<String, ArrayList<DeliveryPossibleAreaDetailModel>>> result_list2) {
        this.result_list = result_list2;
    }
}