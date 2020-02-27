package com.nuvent.shareat.model.delivery;

import android.net.Uri;
import android.text.TextUtils;
import com.nuvent.shareat.model.JsonConvertable;
import com.nuvent.shareat.model.payment.PayModel;
import org.slf4j.Marker;

public class DeliveryPaymentOrderListModel extends JsonConvertable {
    private String address;
    private String addressRest;
    private int count;
    private int dateSno;
    private String dateYmd;
    private int dayOfWeek;
    private int deliverPrice;
    public String group_pay_status_text;
    private int itemPrice;
    private String menuImagePath;
    private String menuName;
    private String menuOriginPrice;
    private String menuPrice;
    private int menuSno;
    private String orderName;
    private String orderPhone;
    public String partner_name1;
    private String pay_real;
    private String pay_total;
    private int price;
    private String receiveName;
    private String receivePhone;
    private String requestMessage;
    private String status;
    private String statusText;
    private String useSafePhone;
    public PayModel[] user_list;
    private String zipCode;

    public String getRequestMessage() {
        return this.requestMessage;
    }

    public void setRequestMessage(String requestMessage2) {
        this.requestMessage = requestMessage2;
    }

    public String getOrderPhone() {
        return this.orderPhone;
    }

    public void setOrderPhone(String orderPhone2) {
        this.orderPhone = orderPhone2;
    }

    public int getMenuSno() {
        return this.menuSno;
    }

    public void setMenuSno(int menuSno2) {
        this.menuSno = menuSno2;
    }

    public int getCount() {
        return this.count;
    }

    public void setCount(int count2) {
        this.count = count2;
    }

    public String getStatus() {
        return this.status;
    }

    public void setStatus(String status2) {
        this.status = status2;
    }

    public String getOrderName() {
        return this.orderName;
    }

    public void setOrderName(String orderName2) {
        this.orderName = orderName2;
    }

    public String getUseSafePhone() {
        return this.useSafePhone;
    }

    public void setUseSafePhone(String useSafePhone2) {
        this.useSafePhone = useSafePhone2;
    }

    public String getReceivePhone() {
        return this.receivePhone;
    }

    public void setReceivePhone(String receivePhone2) {
        this.receivePhone = receivePhone2;
    }

    public String getStatusText() {
        return this.statusText;
    }

    public void setStatusText(String statusText2) {
        this.statusText = statusText2;
    }

    public int getItemPrice() {
        return this.itemPrice;
    }

    public void setItemPrice(int itemPrice2) {
        this.itemPrice = itemPrice2;
    }

    public int getPrice() {
        return this.price;
    }

    public void setPrice(int price2) {
        this.price = price2;
    }

    public String getDateYmd() {
        return this.dateYmd;
    }

    public void setDateYmd(String dateYmd2) {
        this.dateYmd = dateYmd2;
    }

    public String getAddress() {
        return this.address;
    }

    public void setAddress(String address2) {
        this.address = address2;
    }

    public String getZipCode() {
        return this.zipCode;
    }

    public void setZipCode(String zipCode2) {
        this.zipCode = zipCode2;
    }

    public int getDeliverPrice() {
        return this.deliverPrice;
    }

    public void setDeliverPrice(int deliverPrice2) {
        this.deliverPrice = deliverPrice2;
    }

    public String getReceiveName() {
        return this.receiveName;
    }

    public void setReceiveName(String receiveName2) {
        this.receiveName = receiveName2;
    }

    public String getAddressRest() {
        return this.addressRest;
    }

    public void setAddressRest(String addressRest2) {
        this.addressRest = addressRest2;
    }

    public int getDayOfWeek() {
        return this.dayOfWeek;
    }

    public void setDayOfWeek(int dayOfWeek2) {
        this.dayOfWeek = dayOfWeek2;
    }

    public int getDateSno() {
        return this.dateSno;
    }

    public void setDateSno(int dateSno2) {
        this.dateSno = dateSno2;
    }

    public String getMenuName() {
        return this.menuName;
    }

    public void setMenuName(String menuName2) {
        this.menuName = menuName2;
    }

    public String getMenuImagePath() {
        return this.menuImagePath;
    }

    public void setMenuImagePath(String menuImagePath2) {
        this.menuImagePath = menuImagePath2;
    }

    public String getMenuOriginPrice() {
        return this.menuOriginPrice;
    }

    public void setMenuOriginPrice(String menuOriginPrice2) {
        this.menuOriginPrice = menuOriginPrice2;
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

    public PayModel[] getUser_list() {
        return this.user_list;
    }

    public void setUser_list(PayModel[] user_list2) {
        this.user_list = user_list2;
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

    public String getMenuPrice() {
        return this.menuPrice;
    }

    public void setMenuPrice(String menuPrice2) {
        this.menuPrice = menuPrice2;
    }
}