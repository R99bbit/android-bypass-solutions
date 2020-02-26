package co.habitfactory.signalfinance_embrain.dataset;

import com.google.gson.annotations.SerializedName;

public class PushDataSet {
    @SerializedName("address")
    private String address;
    @SerializedName("dataChannel")
    private String dataChannel;
    @SerializedName("index")
    private String index;
    @SerializedName("isPopup")
    private String isPopup;
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
    @SerializedName("pushDbId")
    private String pushDbId;
    @SerializedName("pushId")
    private String pushId;
    @SerializedName("registrationTimestamp")
    private String registrationTimestamp;
    @SerializedName("remoteIp")
    private String remoteIp;
    @SerializedName("sendToServer")
    private String sendToServer;
    @SerializedName("timestampMillis")
    private String timestampMillis;
    @SerializedName("userAgent")
    private String userAgent;
    @SerializedName("userSimNumber")
    private String userSimNumber;

    public PushDataSet(String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9, String str10, String str11, String str12, String str13, String str14, String str15, String str16, String str17, String str18, String str19, String str20) {
        this.index = str;
        this.pushDbId = str2;
        this.pushId = str3;
        this.userSimNumber = str4;
        this.packageNm = str5;
        this.notiTitle = str6;
        this.notiText = str7;
        this.notiSubText = str8;
        this.notificationBigText = str9;
        this.timestampMillis = str10;
        this.userAgent = str11;
        this.remoteIp = str12;
        this.latitude = str13;
        this.longitude = str14;
        this.address = str15;
        this.provider = str16;
        this.registrationTimestamp = str17;
        this.sendToServer = str18;
        this.isPopup = str19;
        this.dataChannel = str20;
    }

    public PushDataSet(String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9, String str10, String str11, String str12, String str13, String str14, String str15, String str16, String str17, String str18, String str19) {
        this.index = str;
        this.pushId = str2;
        this.userSimNumber = str3;
        this.packageNm = str4;
        this.notiTitle = str5;
        this.notiText = str6;
        this.notiSubText = str7;
        this.notificationBigText = str8;
        this.timestampMillis = str9;
        this.userAgent = str10;
        this.remoteIp = str11;
        this.latitude = str12;
        this.longitude = str13;
        this.address = str14;
        this.provider = str15;
        this.registrationTimestamp = str16;
        this.sendToServer = str17;
        this.isPopup = str18;
        this.dataChannel = str19;
    }

    public String getIndex() {
        return this.index;
    }

    public void setIndex(String str) {
        this.index = str;
    }

    public String getPushDbId() {
        return this.pushDbId;
    }

    public void setPushDbId(String str) {
        this.pushDbId = str;
    }

    public String getPushId() {
        return this.pushId;
    }

    public void setPushId(String str) {
        this.pushId = str;
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

    public String getUserAgent() {
        return this.userAgent;
    }

    public void setUserAgent(String str) {
        this.userAgent = str;
    }

    public String getRemoteIp() {
        return this.remoteIp;
    }

    public void setRemoteIp(String str) {
        this.remoteIp = str;
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

    public String getRegistrationTimestamp() {
        return this.registrationTimestamp;
    }

    public void setRegistrationTimestamp(String str) {
        this.registrationTimestamp = str;
    }

    public String getSendToServer() {
        return this.sendToServer;
    }

    public void setSendToServer(String str) {
        this.sendToServer = str;
    }

    public String getIsPopup() {
        return this.isPopup;
    }

    public void setIsPopup(String str) {
        this.isPopup = str;
    }

    public String getDataChannel() {
        return this.dataChannel;
    }

    public void setDataChannel(String str) {
        this.dataChannel = str;
    }
}