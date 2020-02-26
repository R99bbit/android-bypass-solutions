package co.habitfactory.signalfinance_embrain.retroapi.request.sms;

import co.habitfactory.signalfinance_embrain.retroapi.request.IptCommon;
import com.google.gson.annotations.SerializedName;

public class IptUpdateCashDataManually extends IptCommon {
    @SerializedName("cardApprovalPrice")
    private String cardApprovalPrice;
    @SerializedName("cardApprovalStore")
    private String cardApprovalStore;
    @SerializedName("categoryCodeUser")
    private String categoryCodeUser;
    @SerializedName("memo")
    private String memo;
    @SerializedName("rTimestamp")
    private String rTimestamp;
    @SerializedName("rating")
    private String rating;
    @SerializedName("smsId")
    private String smsId;
    @SerializedName("smsRegistrationTimestamp")
    private String smsRegistrationTimestamp;

    public IptUpdateCashDataManually(String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9) {
        super(str);
        this.smsId = str2;
        this.categoryCodeUser = str3;
        this.cardApprovalPrice = str4;
        this.smsRegistrationTimestamp = str5;
        this.cardApprovalStore = str6;
        this.rating = str7;
        this.memo = str8;
        this.rTimestamp = str9;
    }

    public String getSmsId() {
        return this.smsId;
    }

    public void setSmsId(String str) {
        this.smsId = str;
    }

    public String getCategoryCodeUser() {
        return this.categoryCodeUser;
    }

    public void setCategoryCodeUser(String str) {
        this.categoryCodeUser = str;
    }

    public String getCardApprovalPrice() {
        return this.cardApprovalPrice;
    }

    public void setCardApprovalPrice(String str) {
        this.cardApprovalPrice = str;
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

    public String getRating() {
        return this.rating;
    }

    public void setRating(String str) {
        this.rating = str;
    }

    public String getMemo() {
        return this.memo;
    }

    public void setMemo(String str) {
        this.memo = str;
    }

    public String getrTimestamp() {
        return this.rTimestamp;
    }

    public void setrTimestamp(String str) {
        this.rTimestamp = str;
    }
}