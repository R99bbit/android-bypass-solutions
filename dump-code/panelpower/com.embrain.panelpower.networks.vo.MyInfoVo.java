package com.embrain.panelpower.networks.vo;

public class MyInfoVo extends PanelBasicRequest {
    public String panelId;

    public MyInfoVo(String str) {
        this.panelId = str;
    }
}