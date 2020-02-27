package com.nuvent.shareat.model.user;

import com.nuvent.shareat.model.BaseResultModel;
import java.io.Serializable;
import java.util.ArrayList;

public class CardResultModel extends BaseResultModel implements Serializable {
    private ArrayList<CardModel> card_list;

    public ArrayList<CardModel> getCard_list() {
        if (this.card_list == null) {
            this.card_list = new ArrayList<>();
        }
        return this.card_list;
    }

    public void setCard_list(ArrayList<CardModel> card_list2) {
        this.card_list = card_list2;
    }
}