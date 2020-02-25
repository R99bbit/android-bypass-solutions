package co.habitfactory.signalfinance_embrain.retroapi.request.sms;

import co.habitfactory.signalfinance_embrain.retroapi.request.IptCommon;
import com.google.gson.annotations.SerializedName;

public class IptSaveCashDataManually extends IptCommon {
    @SerializedName("cardApprovalPrice")
    private String cardApprovalPrice;
    @SerializedName("cardApprovalStore")
    private String cardApprovalStore;
    @SerializedName("categoryCodeUser")
    private String categoryCodeUser;
    @SerializedName("memo")
    private String memo;
    @SerializedName("rating")
    private String rating;
    @SerializedName("smsRegistrationTimestamp")
    private String smsRegistrationTimestamp;
    @SerializedName("userSimNumber")
    private String userSimNumber;

    public IptSaveCashDataManually(String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8) {
        super(str);
        this.userSimNumber = str2;
        this.categoryCodeUser = str3;
        this.cardApprovalPrice = str4;
        this.smsRegistrationTimestamp = str5;
        this.cardApprovalStore = str6;
        this.rating = str7;
        this.memo = str8;
    }

    public String getUserSimNumber() {
        return this.userSimNumber;
    }

    public void setUserSimNumber(String str) {
        this.userSimNumber = str;
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
}