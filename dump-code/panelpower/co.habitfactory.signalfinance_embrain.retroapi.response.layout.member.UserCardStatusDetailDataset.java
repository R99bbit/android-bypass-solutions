package co.habitfactory.signalfinance_embrain.retroapi.response.layout.member;

import com.google.gson.annotations.SerializedName;

public class UserCardStatusDetailDataset {
    @SerializedName("cardName")
    private String cardName;
    @SerializedName("cardType")
    private String cardType;
    @SerializedName("companyCode")
    private String companyCode;
    @SerializedName("companyName")
    private String companyName;
    @SerializedName("showCard")
    private String showCard;

    public UserCardStatusDetailDataset(String str, String str2, String str3, String str4, String str5) {
        this.companyName = str;
        this.companyCode = str2;
        this.cardType = str3;
        this.cardName = str4;
        this.showCard = str5;
    }

    public String getCompanyName() {
        return this.companyName;
    }

    public void setCompanyName(String str) {
        this.companyName = str;
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

    public String getShowCard() {
        return this.showCard;
    }

    public void setShowCard(String str) {
        this.showCard = str;
    }
}