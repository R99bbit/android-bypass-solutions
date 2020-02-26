package co.habitfactory.signalfinance_embrain.retroapi.request.sms;

import co.habitfactory.signalfinance_embrain.retroapi.request.IptCommon;
import com.google.gson.annotations.SerializedName;

public class IptSavePushData extends IptCommon {
    @SerializedName("address")
    private String address;
    @SerializedName("dataChannel")
    private String dataChannel;
    @SerializedName("latitude")
    private String latitude;
    @SerializedName("longitude")
    private String longitude;
    @SerializedName("notiSubText")
    private String notiSubText;
    @SerializedName("notiText")
    private String notiText;
    @SerializedName("notiTitle")
    private String notiTitle;
    @SerializedName("notiBigText")
    private String notificationBigText;
    @SerializedName("packageNm")
    private String packageNm;
    @SerializedName("provider")
    private String provider;
    @SerializedName("timestampMillis")
    private String timestampMillis;
    @SerializedName("userSimNumber")
    private String userSimNumber;

    public IptSavePushData(String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9, String str10, String str11, String str12, String str13) {
        super(str);
        this.userSimNumber = str2;
        this.packageNm = str3;
        this.notiTitle = str4;
        this.notiText = str5;
        this.notiSubText = str6;
        this.notificationBigText = str7;
        this.timestampMillis = str8;
        this.latitude = str9;
        this.longitude = str10;
        this.address = str11;
        this.provider = str12;
        this.dataChannel = str13;
    }

    public String getUserSimNumber() {
        return this.userSimNumber;
    }

    public void setUserSimNumber(String str) {
        this.userSimNumber = str;
    }

    public String getPackageNm() {
        return this.packageNm;
    }

    public void setPackageNm(String str) {
        this.packageNm = str;
    }

    public String getNotiTitle() {
        return this.notiTitle;
    }

    public void setNotiTitle(String str) {
        this.notiTitle = str;
    }

    public String getNotiText() {
        return this.notiText;
    }

    public void setNotiText(String str) {
        this.notiText = str;
    }

    public String getNotiSubText() {
        return this.notiSubText;
    }

    public void setNotiSubText(String str) {
        this.notiSubText = str;
    }

    public String getNotificationBigText() {
        return this.notificationBigText;
    }

    public void setNotificationBigText(String str) {
        this.notificationBigText = str;
    }

    public String getTimestampMillis() {
        return this.timestampMillis;
    }

    public void setTimestampMillis(String str) {
        this.timestampMillis = str;
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

    public String getAddress() {
        return this.address;
    }

    public void setAddress(String str) {
        this.address = str;
    }

    public String getProvider() {
        return this.provider;
    }

    public void setProvider(String str) {
        this.provider = str;
    }

    public String getDataChannel() {
        return this.dataChannel;
    }

    public void setDataChannel(String str) {
        this.dataChannel = str;
    }
}