package com.nuvent.shareat.model;

import java.util.ArrayList;

public class BoardResultModel extends BaseResultModel {
    public ArrayList<BoardModel> result_list = new ArrayList<>();

    public ArrayList<BoardModel> getResult_list() {
        if (this.result_list == null) {
            this.result_list = new ArrayList<>();
        }
        return this.result_list;
    }
}