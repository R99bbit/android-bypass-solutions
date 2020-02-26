package com.embrain.panelpower.networks.vo;

public class AgreeEmailVo extends PanelBasicRequest {
    public String emailAgree;
    public String panelId;

    public AgreeEmailVo(String str, String str2) {
        this.panelId = str;
        this.emailAgree = str2;
    }
}