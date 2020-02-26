package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptUpdateLocation extends IptCommon {
    @SerializedName("address")
    private String address;
    @SerializedName("latitude")
    private String latitude;
    @SerializedName("longitude")
    private String longitude;
    @SerializedName("provider")
    private String provider;
    @SerializedName("rTimestamp")
    private String rTimestamp;
    @SerializedName("smsId")
    private String smsId;

    public IptUpdateLocation(String str, String str2, String str3, String str4, String str5, String str6, String str7) {
        super(str);
        this.smsId = str2;
        this.latitude = str3;
        this.longitude = str4;
        this.provider = str5;
        this.address = str6;
        this.rTimestamp = str7;
    }

    public String getSmsId() {
        return this.smsId;
    }

    public void setSmsId(String str) {
        this.smsId = str;
    }

    public String getLatitude() {
        return this.latitude;
    }

    public void setLatitude(String str) {
        this.latitude = str;
    }

    public String getLongitude() {
        return this.longitude;
    }

    public void setLongitude(String str) {
        this.longitude = str;
    }

    public String getProvider() {
        return this.provider;
    }

    public void setProvider(String str) {
        this.provider = str;
    }

    public String getAddress() {
        return this.address;
    }

    public void setAddress(String str) {
        this.address = str;
    }

    public String getrTimestamp() {
        return this.rTimestamp;
    }

    public void setrTimestamp(String str) {
        this.rTimestamp = str;
    }
}