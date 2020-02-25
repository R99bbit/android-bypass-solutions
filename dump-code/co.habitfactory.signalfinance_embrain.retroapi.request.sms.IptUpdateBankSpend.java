package co.habitfactory.signalfinance_embrain.retroapi.request.sms;

import co.habitfactory.signalfinance_embrain.retroapi.request.IptCommon;
import com.google.gson.annotations.SerializedName;

public class IptUpdateBankSpend extends IptCommon {
    @SerializedName("balance")
    private String balance;
    @SerializedName("dataChannel")
    private String dataChannel;
    @SerializedName("memo")
    private String memo;
    @SerializedName("rTimestamp")
    private String rTimestamp;
    @SerializedName("smsId")
    private String smsId;

    public IptUpdateBankSpend(String str, String str2, String str3, String str4, String str5, String str6) {
        super(str);
        this.balance = str2;
        this.smsId = str3;
        this.memo = str4;
        this.rTimestamp = str5;
        this.dataChannel = str6;
    }

    public String getSmsId() {
        return this.smsId;
    }

    public void setSmsId(String str) {
        this.smsId = str;
    }

    public String getBalance() {
        return this.balance;
    }

    public void setBalance(String str) {
        this.balance = str;
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