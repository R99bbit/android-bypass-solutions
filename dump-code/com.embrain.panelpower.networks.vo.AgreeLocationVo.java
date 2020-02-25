package com.embrain.panelpower.networks.vo;

public class AgreeLocationVo extends PanelBasicRequest {
    public String infoLocation;
    public String panelId;

    public AgreeLocationVo(String str, String str2) {
        this.panelId = str;
        this.infoLocation = str2;
    }
}