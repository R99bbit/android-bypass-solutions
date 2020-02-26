package com.embrain.panelpower.networks.vo;

public class AgreeCallVo extends PanelBasicRequest {
    public String callAgree;
    public String panelId;

    public AgreeCallVo(String str, String str2) {
        this.panelId = str;
        this.callAgree = str2;
    }
}