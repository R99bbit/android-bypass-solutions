package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptPushToken extends IptCommon {
    @SerializedName("deviceToken")
    private String deviceToken;
    @SerializedName("userPhoneNumber")
    private String userPhoneNumber;
    @SerializedName("userPhoneType")
    private String userPhoneType;

    public IptPushToken(String str, String str2, String str3, String str4) {
        super(str);
        this.userPhoneNumber = str2;
        this.userPhoneType = str3;
        this.deviceToken = str4;
    }

    public String getUserPhoneNumber() {
        return this.userPhoneNumber;
    }

    public void setUserPhoneNumber(String str) {
        this.userPhoneNumber = str;
    }

    public String getUserPhoneType() {
        return this.userPhoneType;
    }

    public void setUserPhoneType(String str) {
        this.userPhoneType = str;
    }

    public String getDeviceToken() {
        return this.deviceToken;
    }

    public void setDeviceToken(String str) {
        this.deviceToken = str;
    }
}