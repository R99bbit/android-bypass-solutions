package com.nuvent.shareat.model;

public class PointDetailModel extends BaseResultModel {
    private String deal_type;
    private String group_id;
    private String i_use_amt;
    private String limit_end_date;
    private String limit_start_date;
    private String point_description;
    private int point_value;
    private String use_amt;
    private String use_datetime_text;
    private String used_partner_name;

    public String getGroup_id() {
        return this.group_id;
    }

    public void setGroup_id(String group_id2) {
        this.group_id = group_id2;
    }

    public String getUse_amt() {
        return this.use_amt;
    }

    public void setUse_amt(String use_amt2) {
        this.use_amt = use_amt2;
    }

    public String getDeal_type() {
        return this.deal_type;
    }

    public void setDeal_type(String deal_type2) {
        this.deal_type = deal_type2;
    }

    public String getLimit_start_date() {
        return this.limit_start_date;
    }

    public void setLimit_start_date(String limit_start_date2) {
        this.limit_start_date = limit_start_date2;
    }

    public String getLimit_end_date() {
        return this.limit_end_date;
    }

    public void setLimit_end_date(String limit_end_date2) {
        this.limit_end_date = limit_end_date2;
    }

    public String getUse_datetime_text() {
        return this.use_datetime_text;
    }

    public void setUse_datetime_text(String use_datetime_text2) {
        this.use_datetime_text = use_datetime_text2;
    }

    public String getUsed_partner_name() {
        return this.used_partner_name;
    }

    public void setUsed_partner_name(String used_partner_name2) {
        this.used_partner_name = used_partner_name2;
    }

    public String getPoint_description() {
        return "".equals(this.point_description) ? "-" : this.point_description;
    }

    public void setPoint_description(String point_description2) {
        this.point_description = point_description2;
    }

    public int getPoint_value() {
        return this.point_value;
    }

    public void setPoint_value(int point_value2) {
        this.point_value = point_value2;
    }

    public String getI_use_amt() {
        return this.i_use_amt;
    }

    public void setI_use_amt(String i_use_amt2) {
        this.i_use_amt = i_use_amt2;
    }
}