package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptFundList {
    @SerializedName("fundName")
    private String fundName;
    @SerializedName("regMonth")
    private String regMonth;
    @SerializedName("userId")
    private String userId;

    public IptFundList(String str, String str2, String str3) {
        this.userId = str;
        this.regMonth = str2;
        this.fundName = str3;
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

    public String getFundName() {
        return this.fundName;
    }

    public void setFundName(String str) {
        this.fundName = str;
    }
}