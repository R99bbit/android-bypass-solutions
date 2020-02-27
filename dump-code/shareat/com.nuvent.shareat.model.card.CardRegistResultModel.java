package com.nuvent.shareat.model.card;

import com.nuvent.shareat.model.BaseResultModel;

public class CardRegistResultModel extends BaseResultModel {
    public String BillKey;
    public String CardCode;
    public String CardKind;
    public String CardPass;
    public String Tid;
    public String fail_msg;
    public String inicis_resultCode;
    public String inicis_resultMsg;

    public boolean successRegister() {
        return this.result != null && this.result.equals("Y");
    }

    public String registerResultMsg() {
        if (this.result.equals("Y")) {
            if (this.inicis_resultCode == null || !this.inicis_resultCode.equals("00")) {
                return "\uce74\ub4dc\ub97c \ub4f1\ub85d\ud558\uc600\uc2b5\ub2c8\ub2e4.";
            }
            return "\uce74\ub4dc\ub97c \ub4f1\ub85d\ud558\uc600\uc2b5\ub2c8\ub2e4.";
        } else if (this.result.equals("D")) {
            return "\uc774\ubbf8 \ub4f1\ub85d\ub41c \uce74\ub4dc\uc785\ub2c8\ub2e4.";
        } else {
            if (!this.result.equals("L")) {
                return "\uce74\ub4dc \ub4f1\ub85d\uc744 \uc2e4\ud328\ud558\uc600\uc2b5\ub2c8\ub2e4.";
            }
            if (this.fail_msg == null || this.fail_msg.trim().length() <= 0) {
                return "\uce74\ub4dc \uc778\uc99d\uc5d0 \uc2e4\ud328\ud558\uc600\uc2b5\ub2c8\ub2e4.";
            }
            return this.fail_msg;
        }
    }
}