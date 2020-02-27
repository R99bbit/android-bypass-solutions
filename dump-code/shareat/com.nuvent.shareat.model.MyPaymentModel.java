package com.nuvent.shareat.model;

import android.text.TextUtils;
import com.facebook.appevents.AppEventsConstants;
import com.igaworks.interfaces.CommonInterface;
import com.nuvent.shareat.model.payment.MyPaymentsHistoryDetailModel;
import java.io.Serializable;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;

public class MyPaymentModel implements Serializable {
    public String cancel_date_text;
    public int cancel_status;
    public String cancel_status_text;
    public String card_name;
    public String card_no;
    public String card_pay_amt;
    public String card_sno;
    public String cash_pay_amt;
    public int dc_rate;
    public String group_id;
    public boolean isOpen;
    public String order_id;
    public String partner_name1;
    public String partner_sno;
    public String pay_date_text;
    public String pay_group;
    public int pay_individual;
    public String pay_kind;
    public String pay_kind_text;
    private String pay_method;
    public int pay_real;
    public int pay_status;
    public String pay_status_text;
    public int pay_total;
    public String pay_type;
    public String pay_type_text;
    public String pay_user_sno;
    public String person_deal_amt;
    public int person_discount_amt;
    public String person_var;
    public int person_vat;
    private String pin_no;
    public ArrayList<MyPaymentsHistoryDetailModel> result_list = new ArrayList<>();
    public String user_view_name;

    public String getPin_no() {
        return this.pin_no;
    }

    public String getPay_method() {
        return this.pay_method;
    }

    public void setPay_method(String pay_method2) {
        this.pay_method = pay_method2;
    }

    public void setPin_no(String pin_no2) {
        this.pin_no = pin_no2;
    }

    public String getPartner_sno() {
        return this.partner_sno;
    }

    public void setPartner_sno(String partner_sno2) {
        this.partner_sno = partner_sno2;
    }

    public int getPay_total() {
        return this.pay_total;
    }

    public void setPay_total(int pay_total2) {
        this.pay_total = pay_total2;
    }

    public String getCash_pay_amt() {
        return this.cash_pay_amt;
    }

    public void setCash_pay_amt(String cash_pay_amt2) {
        this.cash_pay_amt = cash_pay_amt2;
    }

    public String getCard_pay_amt() {
        return this.card_pay_amt;
    }

    public void setCard_pay_amt(String card_pay_amt2) {
        this.card_pay_amt = card_pay_amt2;
    }

    public int getCancel_status() {
        return this.cancel_status;
    }

    public void setCancel_status(int cancel_status2) {
        this.cancel_status = cancel_status2;
    }

    public String getPerson_deal_amt() {
        return this.person_deal_amt;
    }

    public void setPerson_deal_amt(String person_deal_amt2) {
        this.person_deal_amt = person_deal_amt2;
    }

    public String getCancel_status_text() {
        return this.cancel_status_text;
    }

    public void setCancel_status_text(String cancel_status_text2) {
        this.cancel_status_text = cancel_status_text2;
    }

    public String getPay_kind_text() {
        return this.pay_kind_text;
    }

    public void setPay_kind_text(String pay_kind_text2) {
        this.pay_kind_text = pay_kind_text2;
    }

    public String getOrder_id() {
        return this.order_id;
    }

    public void setOrder_id(String order_id2) {
        this.order_id = order_id2;
    }

    public int getPay_status() {
        return this.pay_status;
    }

    public void setPay_status(int pay_status2) {
        this.pay_status = pay_status2;
    }

    public String getPay_user_sno() {
        return this.pay_user_sno;
    }

    public void setPay_user_sno(String pay_user_sno2) {
        this.pay_user_sno = pay_user_sno2;
    }

    public String getPay_group() {
        return this.pay_group;
    }

    public void setPay_group(String pay_group2) {
        this.pay_group = pay_group2;
    }

    public String getPay_status_text() {
        return this.pay_status_text;
    }

    public void setPay_status_text(String pay_status_text2) {
        this.pay_status_text = pay_status_text2;
    }

    public String getPay_type() {
        return this.pay_type;
    }

    public void setPay_type(String pay_type2) {
        this.pay_type = pay_type2;
    }

    public int getPay_real() {
        return this.pay_real;
    }

    public void setPay_real(int pay_real2) {
        this.pay_real = pay_real2;
    }

    public String getCard_sno() {
        return this.card_sno;
    }

    public void setCard_sno(String card_sno2) {
        this.card_sno = card_sno2;
    }

    public int getPay_individual() {
        return this.pay_individual;
    }

    public void setPay_individual(int pay_individual2) {
        this.pay_individual = pay_individual2;
    }

    public int getPerson_vat() {
        return this.person_vat;
    }

    public void setPerson_vat(int person_vat2) {
        this.person_vat = person_vat2;
    }

    public String getPartner_name1() {
        return this.partner_name1;
    }

    public void setPartner_name1(String partner_name12) {
        this.partner_name1 = partner_name12;
    }

    public String getGroup_id() {
        return this.group_id;
    }

    public void setGroup_id(String group_id2) {
        this.group_id = group_id2;
    }

    public String getUser_view_name() {
        return this.user_view_name;
    }

    public void setUser_view_name(String user_view_name2) {
        this.user_view_name = user_view_name2;
    }

    public String getCard_name() {
        return this.card_name;
    }

    public void setCard_name(String card_name2) {
        this.card_name = card_name2;
    }

    public int getDc_rate() {
        return this.dc_rate;
    }

    public void setDc_rate(int dc_rate2) {
        this.dc_rate = dc_rate2;
    }

    public String getCancel_date_text() {
        return this.cancel_date_text;
    }

    public void setCancel_date_text(String cancel_date_text2) {
        this.cancel_date_text = cancel_date_text2;
    }

    public int getPerson_discount_amt() {
        return this.person_discount_amt;
    }

    public void setPerson_discount_amt(int person_discount_amt2) {
        this.person_discount_amt = person_discount_amt2;
    }

    public String getPay_type_text() {
        return this.pay_type_text;
    }

    public void setPay_type_text(String pay_type_text2) {
        this.pay_type_text = pay_type_text2;
    }

    public String getPay_date_text() {
        return this.pay_date_text;
    }

    public void setPay_date_text(String pay_date_text2) {
        this.pay_date_text = pay_date_text2;
    }

    public String getPay_kind() {
        return this.pay_kind;
    }

    public void setPay_kind(String pay_kind2) {
        this.pay_kind = pay_kind2;
    }

    public String getCard_no() {
        return this.card_no;
    }

    public void setCard_no(String card_no2) {
        this.card_no = card_no2;
    }

    public String getPerson_var() {
        return this.person_var;
    }

    public void setPerson_var(String person_var2) {
        this.person_var = person_var2;
    }

    public String getDateText() {
        if (this.pay_date_text == null) {
            return "";
        }
        SimpleDateFormat format = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT2, Locale.getDefault());
        try {
            Date date = format.parse(this.pay_date_text);
            format.applyPattern("yyyy/MM/dd HH:mm");
            return format.format(date);
        } catch (ParseException e) {
            e.printStackTrace();
            return this.pay_date_text;
        }
    }

    public String getCardText() {
        if (this.card_name == null) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        builder.append(this.card_name);
        if (this.card_no != null) {
            builder.append("-");
            builder.append(this.card_no);
        }
        return builder.toString();
    }

    public String getDetailText() {
        return String.format(Locale.getDefault(), "\ud310\ub9e4\uac00 %,d\uc6d0 - %,d\uc6d0 \ud560\uc778", new Object[]{Integer.valueOf(this.pay_total), Integer.valueOf(this.person_discount_amt)});
    }

    public String getPeopleCount() {
        return (this.pay_type == null || this.pay_type.equals(AppEventsConstants.EVENT_PARAM_VALUE_NO)) ? AppEventsConstants.EVENT_PARAM_VALUE_YES : "2";
    }

    public String getRealPay(String payReal) {
        int real = 0;
        if (!TextUtils.isEmpty(payReal)) {
            real = Integer.parseInt(payReal);
        }
        return String.format(Locale.getDefault(), "%,d", new Object[]{Integer.valueOf(real)});
    }

    public String getPayTotal(String payTotal) {
        int total = 0;
        if (!TextUtils.isEmpty(payTotal)) {
            total = Integer.parseInt(payTotal);
        }
        return String.format(Locale.getDefault(), "%,d", new Object[]{Integer.valueOf(total)});
    }
}