package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptPushResult extends IptCommon {
    @SerializedName("pushId")
    private String pushId;
    @SerializedName("pushType")
    private String pushType;

    public IptPushResult(String str, String str2, String str3) {
        super(str);
        this.pushId = str2;
        this.pushType = str3;
    }

    public String getPushId() {
        return this.pushId;
    }

    public void setPushId(String str) {
        this.pushId = str;
    }

    public String getPushType() {
        return this.pushType;
    }

    public void setPushType(String str) {
        this.pushType = str;
    }
}