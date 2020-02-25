package com.embrain.panelpower.networks.vo;

import com.embrain.panelpower.vo.MyInfo;

public class ResponseMyInfo {
    private static final String SUCCESS = "";
    public MyInfo myInfo;
    public String result;

    public boolean isSuccess() {
        return "success".equals(this.result);
    }

    public MyInfo getMyInfo() {
        if (isSuccess()) {
            return this.myInfo;
        }
        return null;
    }
}