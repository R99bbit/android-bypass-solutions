package com.nuvent.shareat.model.user;

import java.io.Serializable;

public class CardModel implements Serializable {
    private String card_gubun;
    private String card_id;
    private String card_img;
    private String card_name;
    private String card_no;
    private String card_sno;
    private String main_card;
    private String prepaid_card_bal;
    private String use_yn;

    public String getCard_sno() {
        return this.card_sno;
    }

    public void setCard_sno(String card_sno2) {
        this.card_sno = card_sno2;
    }

    public String getCard_id() {
        return this.card_id;
    }

    public void setCard_id(String card_id2) {
        this.card_id = card_id2;
    }

    public String getCard_name() {
        return this.card_name;
    }

    public void setCard_name(String card_name2) {
        this.card_name = card_name2;
    }

    public String getCard_no() {
        return this.card_no;
    }

    public void setCard_no(String card_no2) {
        this.card_no = card_no2;
    }

    public String getUse_yn() {
        return this.use_yn;
    }

    public void setUse_yn(String use_yn2) {
        this.use_yn = use_yn2;
    }

    public String getCard_img() {
        return this.card_img;
    }

    public void setCard_img(String card_img2) {
        this.card_img = card_img2;
    }

    public String getCard_gubun() {
        return this.card_gubun;
    }

    public void setCard_gubun(String card_gubun2) {
        this.card_gubun = card_gubun2;
    }

    public String getPrepaid_card_bal() {
        return this.prepaid_card_bal;
    }

    public void setPrepaid_card_bal(String prepaid_card_bal2) {
        this.prepaid_card_bal = prepaid_card_bal2;
    }

    public String getMain_card() {
        return this.main_card;
    }

    public void setMain_card(String main_card2) {
        this.main_card = main_card2;
    }
}