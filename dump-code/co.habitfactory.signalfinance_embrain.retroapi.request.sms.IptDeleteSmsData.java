package co.habitfactory.signalfinance_embrain.retroapi.request.sms;

import co.habitfactory.signalfinance_embrain.retroapi.request.IptCommon;
import com.google.gson.annotations.SerializedName;

public class IptDeleteSmsData extends IptCommon {
    @SerializedName("rTimestamp")
    private String rTimestamp;
    @SerializedName("smsId")
    private String smsId;

    public IptDeleteSmsData(String str, String str2, String str3) {
        super(str);
        this.smsId = str2;
        this.rTimestamp = str3;
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
}