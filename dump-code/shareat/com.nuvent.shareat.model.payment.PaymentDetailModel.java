package com.nuvent.shareat.model.payment;

import android.text.TextUtils;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Locale;

public class PaymentDetailModel {
    public static String DELIVERY_METHOD_POST = HttpRequest.METHOD_POST;
    public static String DELIVERY_METHOD_QUICK = "QUICK";
    private String address;
    private String address_rest;
    public String cancel_date_text;
    public String cancel_status;
    public String cancel_status_text;
    public String card_name;
    public String card_no;
    public String card_pay_amt;
    public String card_sno;
    public String cash_pay_amt;
    public int count;
    public String coupon_amt;
    public String coupon_sn;
    private String dateYmd;
    public String dc_rate;
    public String dc_rate_add;
    private int delivery_order_id;
    private String displayDateFormat;
    public String group_id;
    public String menu_image_path;
    public String menu_name;
    private int menu_orgin_price;
    private int menu_price;
    public String method;
    public String order_id;
    private String order_name;
    private String order_phone;
    public String partner_name1;
    public String partner_sno;
    public int pay_amt;
    public String pay_date_text;
    public String pay_group;
    public String pay_individual;
    public String pay_kind;
    public String pay_kind_text;
    public String pay_real;
    public String pay_status;
    public String pay_status_text;
    public String pay_total;
    public String pay_type;
    public String pay_type_text;
    public String person_deal_amt;
    public String person_discount_amt;
    public String person_var;
    public String point_amt;
    public String price;
    private String receive_name;
    private String receive_phone;
    private String request_message;
    public GroupUser[] result_list;
    public String status;
    public String user_view_name;
    private String zip_code;

    class GroupUser {
        public String pay_person;
        public String pay_user_img;
        public String pay_user_name;
        public String pay_user_sno;

        GroupUser() {
        }
    }

    public int getMenu_orgin_price() {
        return this.menu_orgin_price;
    }

    public void setMenu_orgin_price(int menu_orgin_price2) {
        this.menu_orgin_price = menu_orgin_price2;
    }

    public int getMenu_price() {
        return this.menu_price;
    }

    public void setMenu_price(int menu_price2) {
        this.menu_price = menu_price2;
    }

    public String pay_date_textSplite(String payDate) {
        String[] split = payDate.split(" ");
        String dateStr = split[0].replace("-", "/");
        return dateStr + getDayStr(dateStr) + (" [" + split[1] + "]");
    }

    public String onDecimalFormat(int value) {
        return new DecimalFormat("#,###").format((long) value);
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

    public String getPersonDiscountAmt(String personDiscountAmt) {
        int amt = 0;
        if (!TextUtils.isEmpty(personDiscountAmt)) {
            amt = Integer.parseInt(personDiscountAmt);
        }
        return String.format(Locale.getDefault(), "%,d", new Object[]{Integer.valueOf(amt)});
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

    public String groupPayStatusStr(String payStatus) {
        switch (Integer.parseInt(payStatus)) {
            case 10:
                return "\uc694\uccad \uc644\ub8cc";
            case 20:
                return "\uacb0\uc81c \uc644\ub8cc";
            case 30:
                return "\uacb0\uc81c \uc644\ub8cc";
            case 40:
                return "\ubd80\ubd84 \uacb0\uc81c \uc2e4\ud328";
            case 50:
                return "\uc804\uccb4 \uacb0\uc81c \uc2e4\ud328";
            case 60:
                return "\uc0ac\uc6a9\uc790 \uacb0\uc81c \ucde8\uc18c";
            default:
                return "";
        }
    }

    public int getDelivery_order_id() {
        return this.delivery_order_id;
    }

    public void setDelivery_order_id(int delivery_order_id2) {
        this.delivery_order_id = delivery_order_id2;
    }

    public String getOrder_name() {
        return this.order_name;
    }

    public void setOrder_name(String order_name2) {
        this.order_name = order_name2;
    }

    public String getOrder_phone() {
        return this.order_phone;
    }

    public void setOrder_phone(String order_phone2) {
        this.order_phone = order_phone2;
    }

    public String getReceive_name() {
        return this.receive_name;
    }

    public void setReceive_name(String receive_name2) {
        this.receive_name = receive_name2;
    }

    public String getZip_code() {
        return this.zip_code;
    }

    public void setZip_code(String zip_code2) {
        this.zip_code = zip_code2;
    }

    public String getAddress() {
        return this.address;
    }

    public void setAddress(String address2) {
        this.address = address2;
    }

    public int getCount() {
        return this.count;
    }

    public void setCount(int count2) {
        this.count = count2;
    }

    public String getPrice() {
        return this.price;
    }

    public void setPrice(String price2) {
        this.price = price2;
    }

    public String getMenu_name() {
        return this.menu_name;
    }

    public void setMenu_name(String menu_name2) {
        this.menu_name = menu_name2;
    }

    public String getStatus() {
        return this.status;
    }

    public void setStatus(String status2) {
        this.status = status2;
    }

    public int getPay_amt() {
        return this.pay_amt;
    }

    public void setPay_amt(int pay_amt2) {
        this.pay_amt = pay_amt2;
    }

    public String getMethod() {
        return this.method;
    }

    public void setMethod(String method2) {
        this.method = method2;
    }

    public String getMenu_image_path() {
        return this.menu_image_path;
    }

    public void setMenu_image_path(String menu_image_path2) {
        this.menu_image_path = menu_image_path2;
    }

    public String getPay_group() {
        return this.pay_group;
    }

    public void setPay_group(String pay_group2) {
        this.pay_group = pay_group2;
    }

    public String getOrder_id() {
        return this.order_id;
    }

    public void setOrder_id(String order_id2) {
        this.order_id = order_id2;
    }

    public String getGroup_id() {
        return this.group_id;
    }

    public void setGroup_id(String group_id2) {
        this.group_id = group_id2;
    }

    public String getPartner_sno() {
        return this.partner_sno;
    }

    public void setPartner_sno(String partner_sno2) {
        this.partner_sno = partner_sno2;
    }

    public String getPartner_name1() {
        return this.partner_name1;
    }

    public void setPartner_name1(String partner_name12) {
        this.partner_name1 = partner_name12;
    }

    public String getPay_status() {
        return this.pay_status;
    }

    public void setPay_status(String pay_status2) {
        this.pay_status = pay_status2;
    }

    public String getPay_status_text() {
        return this.pay_status_text;
    }

    public void setPay_status_text(String pay_status_text2) {
        this.pay_status_text = pay_status_text2;
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

    public String getPay_type() {
        return this.pay_type;
    }

    public void setPay_type(String pay_type2) {
        this.pay_type = pay_type2;
    }

    public String getPay_type_text() {
        return this.pay_type_text;
    }

    public void setPay_type_text(String pay_type_text2) {
        this.pay_type_text = pay_type_text2;
    }

    public String getCard_sno() {
        return this.card_sno;
    }

    public void setCard_sno(String card_sno2) {
        this.card_sno = card_sno2;
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

    public String getPay_date_text() {
        return this.pay_date_text;
    }

    public void setPay_date_text(String pay_date_text2) {
        this.pay_date_text = pay_date_text2;
    }

    public String getUser_view_name() {
        return this.user_view_name;
    }

    public void setUser_view_name(String user_view_name2) {
        this.user_view_name = user_view_name2;
    }

    public String getDc_rate() {
        return this.dc_rate;
    }

    public void setDc_rate(String dc_rate2) {
        this.dc_rate = dc_rate2;
    }

    public String getDc_rate_add() {
        return this.dc_rate_add;
    }

    public void setDc_rate_add(String dc_rate_add2) {
        this.dc_rate_add = dc_rate_add2;
    }

    public String getPay_total() {
        return this.pay_total;
    }

    public void setPay_total(String pay_total2) {
        this.pay_total = pay_total2;
    }

    public String getPay_real() {
        return this.pay_real;
    }

    public void setPay_real(String pay_real2) {
        this.pay_real = pay_real2;
    }

    public String getPay_individual() {
        return this.pay_individual;
    }

    public void setPay_individual(String pay_individual2) {
        this.pay_individual = pay_individual2;
    }

    public String getPerson_discount_amt() {
        return this.person_discount_amt;
    }

    public void setPerson_discount_amt(String person_discount_amt2) {
        this.person_discount_amt = person_discount_amt2;
    }

    public String getCard_pay_amt() {
        return this.card_pay_amt;
    }

    public void setCard_pay_amt(String card_pay_amt2) {
        this.card_pay_amt = card_pay_amt2;
    }

    public String getCash_pay_amt() {
        return this.cash_pay_amt;
    }

    public void setCash_pay_amt(String cash_pay_amt2) {
        this.cash_pay_amt = cash_pay_amt2;
    }

    public String getPerson_deal_amt() {
        return this.person_deal_amt;
    }

    public void setPerson_deal_amt(String person_deal_amt2) {
        this.person_deal_amt = person_deal_amt2;
    }

    public String getPerson_var() {
        return this.person_var;
    }

    public void setPerson_var(String person_var2) {
        this.person_var = person_var2;
    }

    public String getCancel_status() {
        return this.cancel_status;
    }

    public void setCancel_status(String cancel_status2) {
        this.cancel_status = cancel_status2;
    }

    public String getCancel_status_text() {
        return this.cancel_status_text;
    }

    public void setCancel_status_text(String cancel_status_text2) {
        this.cancel_status_text = cancel_status_text2;
    }

    public String getCancel_date_text() {
        return this.cancel_date_text;
    }

    public void setCancel_date_text(String cancel_date_text2) {
        this.cancel_date_text = cancel_date_text2;
    }

    public String getCoupon_sn() {
        return this.coupon_sn;
    }

    public void setCoupon_sn(String coupon_sn2) {
        this.coupon_sn = coupon_sn2;
    }

    public String getCoupon_amt() {
        return this.coupon_amt;
    }

    public void setCoupon_amt(String coupon_amt2) {
        this.coupon_amt = coupon_amt2;
    }

    public String getPoint_amt() {
        return this.point_amt;
    }

    public void setPoint_amt(String point_amt2) {
        this.point_amt = point_amt2;
    }

    public String getReceive_phone() {
        return this.receive_phone;
    }

    public void setReceive_phone(String receive_phone2) {
        this.receive_phone = receive_phone2;
    }

    public String getAddress_rest() {
        return this.address_rest;
    }

    public void setAddress_rest(String address_rest2) {
        this.address_rest = address_rest2;
    }

    public static String getDeliveryMethodQuick() {
        return DELIVERY_METHOD_QUICK;
    }

    public static void setDeliveryMethodQuick(String deliveryMethodQuick) {
        DELIVERY_METHOD_QUICK = deliveryMethodQuick;
    }

    public static String getDeliveryMethodPost() {
        return DELIVERY_METHOD_POST;
    }

    public static void setDeliveryMethodPost(String deliveryMethodPost) {
        DELIVERY_METHOD_POST = deliveryMethodPost;
    }

    public GroupUser[] getResult_list() {
        return this.result_list;
    }

    public void setResult_list(GroupUser[] result_list2) {
        this.result_list = result_list2;
    }

    public String getDateYmd() {
        return this.dateYmd;
    }

    public void setDateYmd(String dateYmd2) {
        this.dateYmd = dateYmd2;
    }

    public String getDisplayDateFormat() {
        return this.displayDateFormat;
    }

    public void setDisplayDateFormat(String displayDateFormat2) {
        this.displayDateFormat = displayDateFormat2;
    }

    public String getRequest_message() {
        return this.request_message;
    }

    public void setRequest_message(String request_message2) {
        this.request_message = request_message2;
    }
}