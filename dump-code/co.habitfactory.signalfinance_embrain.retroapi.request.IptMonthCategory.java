package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptMonthCategory {
    @SerializedName("categoryCode")
    private String categoryCode;
    @SerializedName("regMonth")
    private String regMonth;
    @SerializedName("userId")
    private String userId;

    public IptMonthCategory(String str, String str2, String str3) {
        this.userId = str;
        this.regMonth = str2;
        this.categoryCode = str3;
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

    public String getCategoryCode() {
        return this.categoryCode;
    }

    public void setCategoryCode(String str) {
        this.categoryCode = str;
    }
}