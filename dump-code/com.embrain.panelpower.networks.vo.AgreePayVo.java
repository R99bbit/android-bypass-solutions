package com.embrain.panelpower.networks.vo;

public class AgreePayVo extends PanelBasicRequest {
    public String infoPay;
    public String panelId;

    public AgreePayVo(String str, String str2) {
        this.panelId = str;
        this.infoPay = str2;
    }
}