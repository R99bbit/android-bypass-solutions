package co.habitfactory.signalfinance_embrain.retroapi.request.sms;

import co.habitfactory.signalfinance_embrain.retroapi.request.IptCommon;
import com.google.gson.annotations.SerializedName;

public class IptSaveSmsData extends IptCommon {
    @SerializedName("dataChannel")
    private String dataChannel;
    @SerializedName("displayMessageBody")
    private String displayMessageBody;
    @SerializedName("displayOriginatingAddress")
    private String displayOriginatingAddress;
    @SerializedName("messageBody")
    private String messageBody;
    @SerializedName("originatingAddress")
    private String originatingAddress;
    @SerializedName("provider")
    private String provider;
    @SerializedName("serviceCenterAddress")
    private String serviceCenterAddress;
    @SerializedName("timestampMillis")
    private String timestampMillis;
    @SerializedName("userSimNumber")
    private String userSimNumber;

    public IptSaveSmsData(String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9, String str10) {
        super(str);
        this.provider = str2;
        this.serviceCenterAddress = str3;
        this.originatingAddress = str4;
        this.displayOriginatingAddress = str5;
        this.messageBody = str6;
        this.displayMessageBody = str7;
        this.userSimNumber = str8;
        this.timestampMillis = str9;
        this.dataChannel = str10;
    }

    public String getProvider() {
        return this.provider;
    }

    public void setProvider(String str) {
        this.provider = str;
    }

    public String getServiceCenterAddress() {
        return this.serviceCenterAddress;
    }

    public void setServiceCenterAddress(String str) {
        this.serviceCenterAddress = str;
    }

    public String getOriginatingAddress() {
        return this.originatingAddress;
    }

    public void setOriginatingAddress(String str) {
        this.originatingAddress = str;
    }

    public String getDisplayOriginatingAddress() {
        return this.displayOriginatingAddress;
    }

    public void setDisplayOriginatingAddress(String str) {
        this.displayOriginatingAddress = str;
    }

    public String getMessageBody() {
        return this.messageBody;
    }

    public void setMessageBody(String str) {
        this.messageBody = str;
    }

    public String getDisplayMessageBody() {
        return this.displayMessageBody;
    }

    public void setDisplayMessageBody(String str) {
        this.displayMessageBody = str;
    }

    public String getUserSimNumber() {
        return this.userSimNumber;
    }

    public void setUserSimNumber(String str) {
        this.userSimNumber = str;
    }

    public String getTimestampMillis() {
        return this.timestampMillis;
    }

    public void setTimestampMillis(String str) {
        this.timestampMillis = str;
    }

    public String getDataChannel() {
        return this.dataChannel;
    }

    public void setDataChannel(String str) {
        this.dataChannel = str;
    }
}