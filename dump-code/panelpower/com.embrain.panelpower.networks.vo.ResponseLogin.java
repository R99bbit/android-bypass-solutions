package com.embrain.panelpower.networks.vo;

import androidx.annotation.NonNull;
import com.embrain.panelpower.vo.UserSession;
import com.google.gson.Gson;

public class ResponseLogin extends PanelBasicResponse {
    private static final String SUCCESS = "";
    public String loginFailCnt;
    public UserSession userSession;

    public boolean isSuccess() {
        return "success".equals(this.result);
    }

    public UserSession getSession() {
        if (isSuccess()) {
            return this.userSession;
        }
        return null;
    }

    @NonNull
    public String toString() {
        return new Gson().toJson((Object) this);
    }
}