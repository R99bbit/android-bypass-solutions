package com.embrain.panelpower.networks.vo;

public class EventRecommendMsgVO extends PanelBasicRequest {
    public String name;
    public String userId;

    public EventRecommendMsgVO(String str, String str2) {
        this.name = str;
        this.userId = str2;
    }
}