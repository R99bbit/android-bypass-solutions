package com.embrain.panelpower.networks.vo;

public class AgreeMobileVo extends PanelBasicRequest {
    public String panelId;
    public String smsAgree;

    public AgreeMobileVo(String str, String str2) {
        this.panelId = str;
        this.smsAgree = str2;
    }
}