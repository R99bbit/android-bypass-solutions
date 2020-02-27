package com.nuvent.shareat.model;

public class CouponDetailModel extends BaseResultModel {
    private String after_down_expire_date;
    private String cnt_partner;
    private String coupon_division;
    private String coupon_division_text;
    private String coupon_group_sno;
    private String coupon_gubun;
    private String coupon_gubun_text;
    private String coupon_name;
    private String coupon_remark;
    private String coupon_sn;
    private String coupon_status;
    private String coupon_status_text;
    private String coupon_type;
    private String coupon_type_text;
    private int discount_value;
    private String down_end_date;
    private String down_start_date;
    private String expire_date;
    private int expire_period;
    private String expire_type;
    private boolean isChecked;
    private String issue_date;
    private String limit_yn;
    private String min_condition;
    private String min_condition_type;
    private String min_condition_type_text;
    private int remain_cnt;
    private String target_partner_name;
    private String target_partner_yn;
    private String target_partner_yn_text;
    private String term_date;
    private String usable_partner_name;
    private String use_date;
    private String use_partner_name;
    private String use_partner_sno;

    public String getExpire_type() {
        return this.expire_type;
    }

    public int getExpire_period() {
        return this.expire_period;
    }

    public int getRemain_cnt() {
        return this.remain_cnt;
    }

    public String getAfter_down_expire_date() {
        return this.after_down_expire_date;
    }

    public String getUsable_partner_name() {
        return this.usable_partner_name;
    }

    public String getLimit_yn() {
        return this.limit_yn;
    }

    public void setLimit_yn(String limit_yn2) {
        this.limit_yn = limit_yn2;
    }

    public boolean isChecked() {
        return this.isChecked;
    }

    public void setChecked(boolean isChecked2) {
        this.isChecked = isChecked2;
    }

    public String getCoupon_group_sno() {
        return this.coupon_group_sno;
    }

    public String getCoupon_name() {
        return this.coupon_name;
    }

    public String getDown_start_date() {
        return this.down_start_date;
    }

    public String getDown_end_date() {
        return this.down_end_date;
    }

    public String getCoupon_remark() {
        return this.coupon_remark;
    }

    public String getCoupon_division() {
        return this.coupon_division;
    }

    public String getCoupon_division_text() {
        return this.coupon_division_text;
    }

    public String getCoupon_gubun() {
        return this.coupon_gubun;
    }

    public String getCoupon_gubun_text() {
        return this.coupon_gubun_text;
    }

    public String getCoupon_type() {
        return this.coupon_type;
    }

    public String getCoupon_type_text() {
        return this.coupon_type_text;
    }

    public int getDiscount_value() {
        return this.discount_value;
    }

    public String getMin_condition() {
        return this.min_condition;
    }

    public String getMin_condition_type() {
        return this.min_condition_type;
    }

    public String getMin_condition_type_text() {
        return this.min_condition_type_text;
    }

    public String getIssue_date() {
        return this.issue_date;
    }

    public String getExpire_date() {
        return this.expire_date;
    }

    public String getTerm_date() {
        return this.term_date;
    }

    public String getTarget_partner_yn() {
        return this.target_partner_yn;
    }

    public String getTarget_partner_yn_text() {
        return this.target_partner_yn_text;
    }

    public String getTarget_partner_name() {
        return this.target_partner_name;
    }

    public String getCnt_partner() {
        return this.cnt_partner;
    }

    public String getUse_date() {
        return this.use_date;
    }

    public String getUse_partner_sno() {
        return this.use_partner_sno;
    }

    public String getUse_partner_name() {
        return this.use_partner_name;
    }

    public String getCoupon_status() {
        return this.coupon_status;
    }

    public String getCoupon_status_text() {
        return this.coupon_status_text;
    }

    public String getCoupon_sn() {
        return this.coupon_sn;
    }
}