package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptAccountNumber {
    @SerializedName("cardName")
    private String cardName;
    @SerializedName("cardType")
    private String cardType;
    @SerializedName("companyCode")
    private String companyCode;
    @SerializedName("regMonth")
    private String regMonth;
    @SerializedName("userId")
    private String userId;

    public IptAccountNumber(String str, String str2, String str3, String str4, String str5) {
        this.userId = str;
        this.regMonth = str2;
        this.companyCode = str3;
        this.cardType = str4;
        this.cardName = str5;
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

    public String getCompanyCode() {
        return this.companyCode;
    }

    public void setCompanyCode(String str) {
        this.companyCode = str;
    }

    public String getCardType() {
        return this.cardType;
    }

    public void setCardType(String str) {
        this.cardType = str;
    }

    public String getCardName() {
        return this.cardName;
    }

    public void setCardName(String str) {
        this.cardName = str;
    }
}