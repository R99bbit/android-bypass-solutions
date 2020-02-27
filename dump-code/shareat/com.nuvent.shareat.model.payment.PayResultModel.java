package com.nuvent.shareat.model.payment;

import android.net.Uri;
import android.text.TextUtils;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.model.ADBannerDetailModel;
import com.nuvent.shareat.model.JsonConvertable;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Locale;
import org.slf4j.Marker;

public class PayResultModel extends JsonConvertable {
    public ADBannerDetailModel[] ad_list;
    public int dc_rate;
    public int dc_rate_add;
    public int group_id;
    public int group_pay_status;
    public String group_pay_status_text;
    public String partner_menus;
    public String partner_name1;
    public int partner_sno;
    public String pay_date_text;
    public int pay_real;
    public int pay_total;
    public int user_cnt;
    public PayModel[] user_list;

    public int getAdvertiseListLength() {
        return this.ad_list.length;
    }

    public String getAdvertiseSchemeUrl(int index) {
        return this.ad_list[index].getScheme_url();
    }

    public String getAdvertiseImgUrl(int index) {
        return this.ad_list[index].getImg_url();
    }

    public String getAdvertiseSubTitle(int index) {
        return this.ad_list[index].getSub_title();
    }

    public void UriDecode() {
        try {
            if (!TextUtils.isEmpty(this.group_pay_status_text)) {
                this.group_pay_status_text = Uri.decode(this.group_pay_status_text).replace(Marker.ANY_NON_NULL_MARKER, "");
            }
            if (!TextUtils.isEmpty(this.partner_name1)) {
                this.partner_name1 = Uri.decode(this.partner_name1).replace(Marker.ANY_NON_NULL_MARKER, "");
            }
            for (PayModel item : this.user_list) {
                item.UriDecode();
            }
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }

    public int getPayIndividual() {
        String pay_individual = this.user_list[0].pay_individual;
        if (TextUtils.isEmpty(pay_individual)) {
            pay_individual = AppEventsConstants.EVENT_PARAM_VALUE_NO;
        }
        return Integer.parseInt(pay_individual);
    }

    public int getAlonePayAmt() {
        String payAmt = String.valueOf(this.user_list[0].pay_amt);
        if (TextUtils.isEmpty(payAmt)) {
            payAmt = AppEventsConstants.EVENT_PARAM_VALUE_NO;
        }
        return Integer.parseInt(payAmt);
    }

    public String getPayTotal(String payTotal) {
        int total = 0;
        if (!TextUtils.isEmpty(payTotal)) {
            total = Integer.parseInt(payTotal);
        }
        return String.format(Locale.getDefault(), "%,d", new Object[]{Integer.valueOf(total)});
    }

    public String pay_date_textSplite() {
        if (TextUtils.isEmpty(this.pay_date_text)) {
            return "";
        }
        String[] split = this.pay_date_text.split(" ");
        String dateStr = split[0].replace("-", "/");
        return dateStr + getDayStr(dateStr) + (" [" + split[1] + "]");
    }

    private String getDayStr(String dateStr) {
        String[] dayStrs = {"", "\uc77c", "\uc6d4", "\ud654", "\uc218", "\ubaa9", "\uae08", "\ud1a0"};
        String resultDay = "";
        try {
            Calendar calender = Calendar.getInstance();
            calender.setTime(new SimpleDateFormat("yyyy/MM/dd").parse(dateStr));
            resultDay = dayStrs[calender.get(7)];
        } catch (ParseException e) {
            e.printStackTrace();
            System.out.println(getClass().getName() + " " + e.toString());
        }
        return " " + resultDay;
    }

    public int getDiscountValue() {
        return this.pay_total - this.pay_real;
    }

    public boolean groupPayStatus() {
        switch (this.group_pay_status) {
            case 10:
            case 20:
            case 30:
                return true;
            case 40:
            case 50:
            case 60:
            case 99:
                return false;
            default:
                return false;
        }
    }

    public int getPartner_sno() {
        return this.partner_sno;
    }

    public void setPartner_sno(int partner_sno2) {
        this.partner_sno = partner_sno2;
    }

    public int getPay_total() {
        return this.pay_total;
    }

    public void setPay_total(int pay_total2) {
        this.pay_total = pay_total2;
    }

    public int getDc_rate() {
        return this.dc_rate;
    }

    public void setDc_rate(int dc_rate2) {
        this.dc_rate = dc_rate2;
    }

    public int getUser_cnt() {
        return this.user_cnt;
    }

    public void setUser_cnt(int user_cnt2) {
        this.user_cnt = user_cnt2;
    }

    public int getPay_real() {
        return this.pay_real;
    }

    public void setPay_real(int pay_real2) {
        this.pay_real = pay_real2;
    }

    public int getGroup_id() {
        return this.group_id;
    }

    public void setGroup_id(int group_id2) {
        this.group_id = group_id2;
    }

    public int getDc_rate_add() {
        return this.dc_rate_add;
    }

    public void setDc_rate_add(int dc_rate_add2) {
        this.dc_rate_add = dc_rate_add2;
    }

    public int getGroup_pay_status() {
        return this.group_pay_status;
    }

    public void setGroup_pay_status(int group_pay_status2) {
        this.group_pay_status = group_pay_status2;
    }

    public String getPay_date_text() {
        return this.pay_date_text;
    }

    public void setPay_date_text(String pay_date_text2) {
        this.pay_date_text = pay_date_text2;
    }

    public String getPartner_name1() {
        return this.partner_name1;
    }

    public void setPartner_name1(String partner_name12) {
        this.partner_name1 = partner_name12;
    }

    public PayModel[] getUser_list() {
        return this.user_list;
    }

    public void setUser_list(PayModel[] user_list2) {
        this.user_list = user_list2;
    }

    public ADBannerDetailModel[] getAd_list() {
        return this.ad_list;
    }

    public void setAd_list(ADBannerDetailModel[] ad_list2) {
        this.ad_list = ad_list2;
    }

    public String getGroup_pay_status_text() {
        return this.group_pay_status_text;
    }

    public void setGroup_pay_status_text(String group_pay_status_text2) {
        this.group_pay_status_text = group_pay_status_text2;
    }

    public String getPartner_menus() {
        return this.partner_menus;
    }

    public void setPartner_menus(String partner_menus2) {
        this.partner_menus = partner_menus2;
    }
}