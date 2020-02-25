package co.habitfactory.signalfinance_embrain.retroapi.response.layout.sms;

import co.habitfactory.signalfinance_embrain.retroapi.response.OptResultDataset;
import com.google.gson.annotations.SerializedName;

public class OptSaveSmsData extends OptResultDataset {
    @SerializedName("cardApprovalPrice")
    private String cardApprovalPrice;
    @SerializedName("cardApprovalStore")
    private String cardApprovalStore;
    @SerializedName("cardApprovalType")
    private String cardApprovalType;
    @SerializedName("cardType")
    private String cardType;
    @SerializedName("categoryCode")
    private String categoryCode;
    @SerializedName("categoryMonthCount")
    private String categoryMonthCount;
    @SerializedName("categoryMonthSum")
    private String categoryMonthSum;
    @SerializedName("categoryName")
    private String categoryName;
    @SerializedName("gpsStatus")
    private String gpsStatus;
    @SerializedName("parseType")
    private String parseType;
    @SerializedName("rTimestamp")
    private String rTimestamp;
    @SerializedName("smsId")
    private String smsId;
    @SerializedName("todaySum")
    private String todaySum;

    public OptSaveSmsData(String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9, String str10, String str11, String str12, String str13, String str14, String str15) {
        super(str, str2);
        this.gpsStatus = str3;
        this.smsId = str4;
        this.rTimestamp = str5;
        this.categoryCode = str6;
        this.cardApprovalStore = str7;
        this.cardApprovalPrice = str8;
        this.cardType = str9;
        this.parseType = str10;
        this.cardApprovalType = str11;
        this.todaySum = str12;
        this.categoryMonthSum = str13;
        this.categoryMonthCount = str14;
        this.categoryName = str15;
    }

    public String getGpsStatus() {
        return this.gpsStatus;
    }

    public void setGpsStatus(String str) {
        this.gpsStatus = str;
    }

    public String getSmsId() {
        return this.smsId;
    }

    public void setSmsId(String str) {
        this.smsId = str;
    }

    public String getrTimestamp() {
        return this.rTimestamp;
    }

    public void setrTimestamp(String str) {
        this.rTimestamp = str;
    }

    public String getCategoryCode() {
        return this.categoryCode;
    }

    public void setCategoryCode(String str) {
        this.categoryCode = str;
    }

    public String getCardApprovalStore() {
        return this.cardApprovalStore;
    }

    public void setCardApprovalStore(String str) {
        this.cardApprovalStore = str;
    }

    public String getCardApprovalPrice() {
        return this.cardApprovalPrice;
    }

    public void setCardApprovalPrice(String str) {
        this.cardApprovalPrice = str;
    }

    public String getCardType() {
        return this.cardType;
    }

    public void setCardType(String str) {
        this.cardType = str;
    }

    public String getParseType() {
        return this.parseType;
    }

    public void setParseType(String str) {
        this.parseType = str;
    }

    public String getCardApprovalType() {
        return this.cardApprovalType;
    }

    public void setCardApprovalType(String str) {
        this.cardApprovalType = str;
    }

    public String getTodaySum() {
        return this.todaySum;
    }

    public void setTodaySum(String str) {
        this.todaySum = str;
    }

    public String getCategoryMonthSum() {
        return this.categoryMonthSum;
    }

    public void setCategoryMonthSum(String str) {
        this.categoryMonthSum = str;
    }

    public String getCategoryMonthCount() {
        return this.categoryMonthCount;
    }

    public void setCategoryMonthCount(String str) {
        this.categoryMonthCount = str;
    }

    public String getCategoryName() {
        return this.categoryName;
    }

    public void setCategoryName(String str) {
        this.categoryName = str;
    }
}