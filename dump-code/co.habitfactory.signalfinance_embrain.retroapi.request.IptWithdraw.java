package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptWithdraw extends IptCommon {
    @SerializedName("reason")
    private String reason;

    public IptWithdraw(String str, String str2) {
        super(str);
        this.reason = str2;
    }

    public String getReason() {
        return this.reason;
    }

    public void setReason(String str) {
        this.reason = str;
    }
}