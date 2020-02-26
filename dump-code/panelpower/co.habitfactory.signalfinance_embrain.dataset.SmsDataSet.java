package co.habitfactory.signalfinance_embrain.dataset;

public class SmsDataSet {
    private String address;
    private String displayMessageBody;
    private String displayOriginatingAddress;
    private String index;
    private String isPopup;
    private String latitude;
    private String longitude;
    private String messageBody;
    private String originatingAddress;
    private String provider;
    private String registrationTimestamp;
    private String remoteIp;
    private String sendToServer;
    private String serviceCenterAddress;
    private String smsDbId;
    private String smsId;
    private String smsMd5;
    private String timestampMillis;
    private String userAgent;
    private String userSimNumber;

    public SmsDataSet(String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9, String str10, String str11, String str12, String str13, String str14, String str15, String str16, String str17, String str18, String str19, String str20) {
        this.index = str;
        this.smsDbId = str2;
        this.smsId = str3;
        this.userSimNumber = str4;
        this.displayMessageBody = str5;
        this.messageBody = str6;
        this.displayOriginatingAddress = str7;
        this.originatingAddress = str8;
        this.serviceCenterAddress = str9;
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
        this.smsMd5 = str20;
    }

    public String getIndex() {
        return this.index;
    }

    public void setIndex(String str) {
        this.index = str;
    }

    public String getSmsDbId() {
        return this.smsDbId;
    }

    public void setSmsDbId(String str) {
        this.smsDbId = str;
    }

    public String getSmsId() {
        return this.smsId;
    }

    public void setSmsId(String str) {
        this.smsId = str;
    }

    public String getUserSimNumber() {
        return this.userSimNumber;
    }

    public void setUserSimNumber(String str) {
        this.userSimNumber = str;
    }

    public String getDisplayMessageBody() {
        return this.displayMessageBody;
    }

    public void setDisplayMessageBody(String str) {
        this.displayMessageBody = str;
    }

    public String getMessageBody() {
        return this.messageBody;
    }

    public void setMessageBody(String str) {
        this.messageBody = str;
    }

    public String getDisplayOriginatingAddress() {
        return this.displayOriginatingAddress;
    }

    public void setDisplayOriginatingAddress(String str) {
        this.displayOriginatingAddress = str;
    }

    public String getOriginatingAddress() {
        return this.originatingAddress;
    }

    public void setOriginatingAddress(String str) {
        this.originatingAddress = str;
    }

    public String getServiceCenterAddress() {
        return this.serviceCenterAddress;
    }

    public void setServiceCenterAddress(String str) {
        this.serviceCenterAddress = str;
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

    public String getSmsMd5() {
        return this.smsMd5;
    }

    public void setSmsMd5(String str) {
        this.smsMd5 = str;
    }
}