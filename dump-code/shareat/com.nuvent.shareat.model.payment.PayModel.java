package com.nuvent.shareat.model.payment;

import android.net.Uri;
import android.text.TextUtils;
import org.slf4j.Marker;

public class PayModel {
    public String cancel_result;
    private String card_name;
    private String card_no;
    public String coupon_amt;
    public String coupon_sn;
    public int order_id;
    public int pay_amt;
    public int pay_group;
    public String pay_individual;
    public String pay_kind;
    public String pay_kind_text;
    public int pay_type;
    public String pay_type_text;
    public String point_amt;
    public int status;
    public String status_text;
    public String user_img;
    public String user_name;
    public int user_sno;

    public boolean isPayStatus() {
        switch (this.status) {
            case 20:
                return true;
            default:
                return false;
        }
    }

    public void UriDecode() {
        try {
            if (!TextUtils.isEmpty(this.pay_kind_text)) {
                this.pay_kind_text = Uri.decode(this.pay_kind_text).replace(Marker.ANY_NON_NULL_MARKER, "");
            }
            if (!TextUtils.isEmpty(this.pay_type_text)) {
                this.pay_type_text = Uri.decode(this.pay_type_text).replace(Marker.ANY_NON_NULL_MARKER, "");
            }
            if (!TextUtils.isEmpty(this.status_text)) {
                this.status_text = Uri.decode(this.status_text).replace(Marker.ANY_NON_NULL_MARKER, "");
            }
            if (!TextUtils.isEmpty(this.user_name)) {
                this.user_name = Uri.decode(this.user_name).replace(Marker.ANY_NON_NULL_MARKER, "");
            }
            if (!TextUtils.isEmpty(this.cancel_result)) {
                this.cancel_result = Uri.decode(this.cancel_result).replace(Marker.ANY_NON_NULL_MARKER, "");
            }
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }

    public int getUser_sno() {
        return this.user_sno;
    }

    public void setUser_sno(int user_sno2) {
        this.user_sno = user_sno2;
    }

    public int getStatus() {
        return this.status;
    }

    public void setStatus(int status2) {
        this.status = status2;
    }

    public String getPoint_amt() {
        return this.point_amt;
    }

    public void setPoint_amt(String point_amt2) {
        this.point_amt = point_amt2;
    }

    public String getCoupon_amt() {
        return this.coupon_amt;
    }

    public void setCoupon_amt(String coupon_amt2) {
        this.coupon_amt = coupon_amt2;
    }

    public int getPay_amt() {
        return this.pay_amt;
    }

    public void setPay_amt(int pay_amt2) {
        this.pay_amt = pay_amt2;
    }

    public String getCoupon_sn() {
        return this.coupon_sn;
    }

    public void setCoupon_sn(String coupon_sn2) {
        this.coupon_sn = coupon_sn2;
    }

    public int getOrder_id() {
        return this.order_id;
    }

    public void setOrder_id(int order_id2) {
        this.order_id = order_id2;
    }

    public int getPay_group() {
        return this.pay_group;
    }

    public void setPay_group(int pay_group2) {
        this.pay_group = pay_group2;
    }

    public int getPay_type() {
        return this.pay_type;
    }

    public void setPay_type(int pay_type2) {
        this.pay_type = pay_type2;
    }

    public String getUser_img() {
        return this.user_img;
    }

    public void setUser_img(String user_img2) {
        this.user_img = user_img2;
    }

    public String getPay_kind() {
        return this.pay_kind;
    }

    public void setPay_kind(String pay_kind2) {
        this.pay_kind = pay_kind2;
    }

    public String getPay_kind_text() {
        return this.pay_kind_text;
    }

    public void setPay_kind_text(String pay_kind_text2) {
        this.pay_kind_text = pay_kind_text2;
    }

    public String getPay_type_text() {
        return this.pay_type_text;
    }

    public void setPay_type_text(String pay_type_text2) {
        this.pay_type_text = pay_type_text2;
    }

    public String getUser_name() {
        return this.user_name;
    }

    public void setUser_name(String user_name2) {
        this.user_name = user_name2;
    }

    public String getStatus_text() {
        return this.status_text;
    }

    public void setStatus_text(String status_text2) {
        this.status_text = status_text2;
    }

    public String getCancel_result() {
        return this.cancel_result;
    }

    public void setCancel_result(String cancel_result2) {
        this.cancel_result = cancel_result2;
    }

    public String getPay_individual() {
        return this.pay_individual;
    }

    public void setPay_individual(String pay_individual2) {
        this.pay_individual = pay_individual2;
    }

    public String getCard_no() {
        return this.card_no;
    }

    public void setCard_no(String card_no2) {
        this.card_no = card_no2;
    }

    public String getCard_name() {
        return this.card_name;
    }

    public void setCard_name(String card_name2) {
        this.card_name = card_name2;
    }
}