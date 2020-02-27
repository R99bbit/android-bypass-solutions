package com.nuvent.shareat.model.delivery;

import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.payment.PayResultModel;
import java.io.Serializable;

public class DeliveryPaymentResultModel extends BaseResultModel implements Serializable {
    private String group_id;
    public int group_pay_status;
    public String group_pay_status_text;
    private String menuImagePath;
    private DeliveryPaymentOrderListModel order_result = new DeliveryPaymentOrderListModel();
    private PayResultModel pay_result = new PayResultModel();
    private String result_message;

    public String getGroup_id() {
        return this.group_id;
    }

    public void setGroup_id(String group_id2) {
        this.group_id = group_id2;
    }

    public PayResultModel getPay_result() {
        return this.pay_result;
    }

    public void setPay_result(PayResultModel pay_result2) {
        this.pay_result = pay_result2;
    }

    public DeliveryPaymentOrderListModel getOrder_result() {
        return this.order_result;
    }

    public void setOrder_result(DeliveryPaymentOrderListModel order_result2) {
        this.order_result = order_result2;
    }

    public String getMenuImagePath() {
        return this.menuImagePath;
    }

    public void setMenuImagePath(String menuImagePath2) {
        this.menuImagePath = menuImagePath2;
    }

    public int getGroup_pay_status() {
        return this.group_pay_status;
    }

    public void setGroup_pay_status(int group_pay_status2) {
        this.group_pay_status = group_pay_status2;
    }

    public String getGroup_pay_status_text() {
        return this.group_pay_status_text;
    }

    public void setGroup_pay_status_text(String group_pay_status_text2) {
        this.group_pay_status_text = group_pay_status_text2;
    }

    public String getResult_message() {
        return this.result_message;
    }

    public void setResult_message(String result_message2) {
        this.result_message = result_message2;
    }
}