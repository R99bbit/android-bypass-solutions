package com.nuvent.shareat.model.delivery;

import com.nuvent.shareat.model.BaseResultModel;
import java.io.Serializable;
import java.util.ArrayList;

public class DeliveryObjectInfoResultModel extends BaseResultModel implements Serializable {
    private String limitPerPerson;
    private String menuImagePath;
    private String menuName;
    private String menuOriginPrice;
    private String menuPrice;
    private String method;
    private String partnerName;
    private ArrayList<DeliveryPossibleDateModel> result_list = new ArrayList<>();

    public String getLimitPerPerson() {
        return this.limitPerPerson;
    }

    public void setLimitPerPerson(String limitPerPerson2) {
        this.limitPerPerson = limitPerPerson2;
    }

    public String getPartnerName() {
        return this.partnerName;
    }

    public void setPartnerName(String partnerName2) {
        this.partnerName = partnerName2;
    }

    public String getMenuImagePath() {
        return this.menuImagePath;
    }

    public void setMenuImagePath(String menuImagePath2) {
        this.menuImagePath = menuImagePath2;
    }

    public String getMenuName() {
        return this.menuName;
    }

    public void setMenuName(String menuName2) {
        this.menuName = menuName2;
    }

    public ArrayList<DeliveryPossibleDateModel> getResult_list() {
        return this.result_list;
    }

    public void setResult_list(ArrayList<DeliveryPossibleDateModel> result_list2) {
        this.result_list = result_list2;
    }

    public String getMenuPrice() {
        return this.menuPrice;
    }

    public void setMenuPrice(String menuPrice2) {
        this.menuPrice = menuPrice2;
    }

    public String getMenuOriginPrice() {
        return this.menuOriginPrice;
    }

    public void setMenuOriginPrice(String menuOriginPrice2) {
        this.menuOriginPrice = menuOriginPrice2;
    }

    public String getMethod() {
        return this.method;
    }

    public void setMethod(String method2) {
        this.method = method2;
    }
}