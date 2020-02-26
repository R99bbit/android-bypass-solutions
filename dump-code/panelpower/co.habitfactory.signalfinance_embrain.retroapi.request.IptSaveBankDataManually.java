package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptSaveBankDataManually extends IptCommon {
    @SerializedName("cardApprovalAmountBalance")
    private String cardApprovalAmountBalance;
    @SerializedName("cardApprovalPrice")
    private String cardApprovalPrice;
    @SerializedName("cardApprovalStore")
    private String cardApprovalStore;
    @SerializedName("cardApprovalType")
    private String cardApprovalType;
    @SerializedName("cardName")
    private String cardName;
    @SerializedName("cardType")
    private String cardType;
    @SerializedName("companyCode")
    private String companyCode;
    @SerializedName("companyName")
    private String companyName;
    @SerializedName("dataChannel")
    private String dataChannel;
    @SerializedName("memo")
    private String memo;
    @SerializedName("smsRegistrationTimestamp")
    private String smsRegistrationTimestamp;
    @SerializedName("userSimNumber")
    private String userSimNumber;

    public IptSaveBankDataManually(String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9, String str10, String str11, String str12, String str13) {
        super(str);
        this.userSimNumber = str2;
        this.companyCode = str3;
        this.companyName = str4;
        this.cardName = str5;
        this.cardType = str6;
        this.cardApprovalType = str7;
        this.cardApprovalPrice = str8;
        this.cardApprovalAmountBalance = str9;
        this.smsRegistrationTimestamp = str10;
        this.cardApprovalStore = str11;
        this.memo = str12;
        this.dataChannel = str13;
    }

    public String getUserSimNumber() {
        return this.userSimNumber;
    }

    public void setUserSimNumber(String str) {
        this.userSimNumber = str;
    }

    public String getCompanyCode() {
        return this.companyCode;
    }

    public void setCompanyCode(String str) {
        this.companyCode = str;
    }

    public String getCompanyName() {
        return this.companyName;
    }

    public void setCompanyName(String str) {
        this.companyName = str;
    }

    public String getCardName() {
        return this.cardName;
    }

    public void setCardName(String str) {
        this.cardName = str;
    }

    public String getCardType() {
        return this.cardType;
    }

    public void setCardType(String str) {
        this.cardType = str;
    }

    public String getCardApprovalType() {
        return this.cardApprovalType;
    }

    public void setCardApprovalType(String str) {
        this.cardApprovalType = str;
    }

    public String getCardApprovalPrice() {
        return this.cardApprovalPrice;
    }

    public void setCardApprovalPrice(String str) {
        this.cardApprovalPrice = str;
    }

    public String getCardApprovalAmountBalance() {
        return this.cardApprovalAmountBalance;
    }

    public void setCardApprovalAmountBalance(String str) {
        this.cardApprovalAmountBalance = str;
    }

    public String getSmsRegistrationTimestamp() {
        return this.smsRegistrationTimestamp;
    }

    public void setSmsRegistrationTimestamp(String str) {
        this.smsRegistrationTimestamp = str;
    }

    public String getCardApprovalStore() {
        return this.cardApprovalStore;
    }

    public void setCardApprovalStore(String str) {
        this.cardApprovalStore = str;
    }

    public String getMemo() {
        return this.memo;
    }

    public void setMemo(String str) {
        this.memo = str;
    }

    public String getDataChannel() {
        return this.dataChannel;
    }

    public void setDataChannel(String str) {
        this.dataChannel = str;
    }
}