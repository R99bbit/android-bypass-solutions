package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptExceptionCard extends IptCommon {
    @SerializedName("cardNumber")
    private String cardNumber;
    @SerializedName("cardType")
    private String cardType;
    @SerializedName("companyCode")
    private String companyCode;
    @SerializedName("doNotShow")
    private String doNotShow;

    public IptExceptionCard(String str, String str2, String str3, String str4, String str5) {
        super(str);
        this.companyCode = str2;
        this.cardType = str3;
        this.cardNumber = str4;
        this.doNotShow = str5;
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

    public String getCardNumber() {
        return this.cardNumber;
    }

    public void setCardNumber(String str) {
        this.cardNumber = str;
    }

    public String getDoNotShow() {
        return this.doNotShow;
    }

    public void setDoNotShow(String str) {
        this.doNotShow = str;
    }
}