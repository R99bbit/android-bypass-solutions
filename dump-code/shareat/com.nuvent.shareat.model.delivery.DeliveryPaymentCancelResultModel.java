package com.nuvent.shareat.model.delivery;

import com.nuvent.shareat.model.BaseResultModel;
import java.io.Serializable;

public class DeliveryPaymentCancelResultModel extends BaseResultModel implements Serializable {
    private String err_msg;

    public String getErr_msg() {
        return this.err_msg;
    }

    public void setErr_msg(String err_msg2) {
        this.err_msg = err_msg2;
    }
}