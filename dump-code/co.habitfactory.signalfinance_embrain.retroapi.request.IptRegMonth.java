package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptRegMonth {
    @SerializedName("regMonth")
    private String regMonth;
    @SerializedName("userId")
    private String userId;

    public IptRegMonth(String str, String str2) {
        this.userId = str;
        this.regMonth = str2;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String str) {
        this.userId = str;
    }

    public String getRegMonth() {
        return this.regMonth;
    }

    public void setRegMonth(String str) {
        this.regMonth = str;
    }
}