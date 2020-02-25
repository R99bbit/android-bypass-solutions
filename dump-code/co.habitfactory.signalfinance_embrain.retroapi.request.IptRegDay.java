package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptRegDay {
    @SerializedName("regDate")
    private String regDate;
    @SerializedName("userId")
    private String userId;

    public IptRegDay(String str, String str2) {
        this.userId = str;
        this.regDate = str2;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String str) {
        this.userId = str;
    }

    public String getRegDate() {
        return this.regDate;
    }

    public void setRegDate(String str) {
        this.regDate = str;
    }
}