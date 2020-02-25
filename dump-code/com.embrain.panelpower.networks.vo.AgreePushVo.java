package com.embrain.panelpower.networks.vo;

public class AgreePushVo extends PanelBasicRequest {
    public String panelId;
    public String pushSurveyOnline;

    public AgreePushVo(String str, String str2) {
        this.panelId = str;
        this.pushSurveyOnline = str2;
    }
}