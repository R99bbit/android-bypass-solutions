package com.embrain.panelpower.networks.vo;

import com.embrain.panelpower.UserInfoManager;

public class AgreeUsageVo extends PanelBasicRequest {
    public String expAgreeYn = UserInfoManager.AGREE_Y;
    public String infoExt;
    public String panelId;

    public AgreeUsageVo(String str, String str2) {
        this.panelId = str;
        this.infoExt = str2;
    }
}