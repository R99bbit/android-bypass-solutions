package com.embrain.panelpower.networks.vo;

public class AlarmListVo extends PanelBasicRequest {
    public String panelid;

    public AlarmListVo(String str) {
        this.panelid = str;
    }
}