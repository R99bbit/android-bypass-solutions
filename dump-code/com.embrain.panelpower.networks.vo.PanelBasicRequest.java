package com.embrain.panelpower.networks.vo;

import com.google.gson.Gson;

public class PanelBasicRequest {
    public String toJson() {
        return new Gson().toJson((Object) this);
    }
}