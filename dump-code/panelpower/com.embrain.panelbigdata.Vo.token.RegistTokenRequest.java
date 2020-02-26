package com.embrain.panelbigdata.Vo.token;

import com.embrain.panelbigdata.Vo.EmBasicRequest;

public class RegistTokenRequest extends EmBasicRequest {
    public String ad_id;
    public String panel_id;
    public String token;

    public String getPanel_id() {
        return this.panel_id;
    }

    public String getAd_id() {
        return this.ad_id;
    }

    public String getToken() {
        return this.token;
    }
}