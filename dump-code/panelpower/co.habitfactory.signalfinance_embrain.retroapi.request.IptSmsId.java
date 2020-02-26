package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptSmsId {
    @SerializedName("smsId")
    private String smsId;
    @SerializedName("userId")
    private String userId;

    public IptSmsId(String str, String str2) {
        this.userId = str;
        this.smsId = str2;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String str) {
        this.userId = str;
    }

    public String getSmsId() {
        return this.smsId;
    }

    public void setSmsId(String str) {
        this.smsId = str;
    }
}