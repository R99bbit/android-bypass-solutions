package com.nuvent.shareat.model.delivery;

import com.nuvent.shareat.model.JsonConvertable;

public class DeliveryPossibleDateModel extends JsonConvertable {
    private String dateSno;
    private String displayDateFormat;
    private String itemCount;
    private String userItemCount;
    private String viewYn;

    public String getDisplayDateFormat() {
        return this.displayDateFormat;
    }

    public void setDisplayDateFormat(String displayDateFormat2) {
        this.displayDateFormat = displayDateFormat2;
    }

    public String getViewYn() {
        return this.viewYn;
    }

    public void setViewYn(String viewYn2) {
        this.viewYn = viewYn2;
    }

    public String getItemCount() {
        return this.itemCount;
    }

    public void setItemCount(String itemCount2) {
        this.itemCount = itemCount2;
    }

    public String getDateSno() {
        return this.dateSno;
    }

    public void setDateSno(String dateSno2) {
        this.dateSno = dateSno2;
    }

    public String getUserItemCount() {
        return this.userItemCount;
    }

    public void setUserItemCount(String userItemCount2) {
        this.userItemCount = userItemCount2;
    }
}