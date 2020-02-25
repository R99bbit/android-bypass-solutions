package com.embrain.panelpower.networks.vo;

import com.embrain.panelbigdata.utils.StringUtils;
import com.embrain.panelpower.IConstValue.Parameter;

public class PanelBasicResponse {
    public String errorMsg;
    public String msg;
    public String result;
    public String totSize;
    public String type;

    public boolean isSuccess() {
        if (StringUtils.isEmpty(this.result)) {
            return false;
        }
        return this.result.equals("success");
    }

    public boolean isExist() {
        if (StringUtils.isEmpty(this.result)) {
            return false;
        }
        return !this.result.equals(Parameter.NOT_EXIST);
    }

    public boolean isResultExist() {
        if (StringUtils.isEmpty(this.result)) {
            return false;
        }
        return this.result.equals(Parameter.EXIST);
    }

    public boolean isLimit() {
        if (StringUtils.isEmpty(this.result)) {
            return false;
        }
        return this.result.equals("limit");
    }

    public String getErrorMsg() {
        if (StringUtils.isEmpty(this.errorMsg)) {
            return "-";
        }
        return this.errorMsg;
    }

    public boolean isNoPermit() {
        if (StringUtils.isEmpty(this.result)) {
            return false;
        }
        return this.result.equals("no-permit");
    }
}