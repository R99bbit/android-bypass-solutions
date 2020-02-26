package com.embrain.panelbigdata.Vo;

import com.google.gson.Gson;

public class EmBasicRequest {
    public String toJson() {
        return new Gson().toJson((Object) this);
    }
}