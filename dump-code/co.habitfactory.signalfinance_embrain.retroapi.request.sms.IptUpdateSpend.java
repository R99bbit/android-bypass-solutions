package co.habitfactory.signalfinance_embrain.retroapi.request.sms;

import co.habitfactory.signalfinance_embrain.retroapi.request.IptCommon;
import com.google.gson.annotations.SerializedName;

public class IptUpdateSpend extends IptCommon {
    @SerializedName("categoryCode")
    private String categoryCode;
    @SerializedName("dataChannel")
    private String dataChannel;
    @SerializedName("memo")
    private String memo;
    @SerializedName("rTimestamp")
    private String rTimestamp;
    @SerializedName("rating")
    private String rating;
    @SerializedName("smsId")
    private String smsId;

    public IptUpdateSpend(String str, String str2, String str3, String str4, String str5, String str6, String str7) {
        super(str);
        this.smsId = str2;
        this.categoryCode = str3;
        this.rating = str4;
        this.memo = str5;
        this.rTimestamp = str6;
        this.dataChannel = str7;
    }

    public String getSmsId() {
        return this.smsId;
    }

    public void setSmsId(String str) {
        this.smsId = str;
    }

    public String getCategoryCode() {
        return this.categoryCode;
    }

    public void setCategoryCode(String str) {
        this.categoryCode = str;
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

    public String getDataChannel() {
        return this.dataChannel;
    }

    public void setDataChannel(String str) {
        this.dataChannel = str;
    }
}