package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptMemo {
    @SerializedName("memo")
    private String memo;
    @SerializedName("userId")
    private String userId;

    public IptMemo(String str, String str2) {
        this.userId = str;
        this.memo = str2;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String str) {
        this.userId = str;
    }

    public String getMemo() {
        return this.memo;
    }

    public void setMemo(String str) {
        this.memo = str;
    }
}