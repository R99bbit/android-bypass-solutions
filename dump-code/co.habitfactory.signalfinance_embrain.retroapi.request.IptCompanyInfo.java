package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptCompanyInfo {
    @SerializedName("cardName")
    private String cardName;
    @SerializedName("companyCode")
    private String companyCode;
    @SerializedName("userId")
    private String userId;

    public IptCompanyInfo(String str, String str2, String str3) {
        this.userId = str;
        this.companyCode = str2;
        this.cardName = str3;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String str) {
        this.userId = str;
    }

    public String getCompanyCode() {
        return this.companyCode;
    }

    public void setCompanyCode(String str) {
        this.companyCode = str;
    }

    public String getCardName() {
        return this.cardName;
    }

    public void setCardName(String str) {
        this.cardName = str;
    }
}