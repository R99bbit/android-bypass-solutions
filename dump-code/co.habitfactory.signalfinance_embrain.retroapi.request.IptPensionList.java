package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptPensionList {
    @SerializedName("pensionName")
    private String pensionName;
    @SerializedName("regMonth")
    private String regMonth;
    @SerializedName("userId")
    private String userId;

    public IptPensionList(String str, String str2, String str3) {
        this.userId = str;
        this.regMonth = str2;
        this.pensionName = str3;
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

    public String getPensionName() {
        return this.pensionName;
    }

    public void setPensionName(String str) {
        this.pensionName = str;
    }
}