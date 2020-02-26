package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptCommon {
    @SerializedName("userId")
    private String userId;

    public IptCommon(String str) {
        this.userId = str;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String str) {
        this.userId = str;
    }
}