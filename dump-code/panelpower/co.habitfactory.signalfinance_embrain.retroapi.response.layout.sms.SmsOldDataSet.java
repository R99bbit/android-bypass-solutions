package co.habitfactory.signalfinance_embrain.retroapi.response.layout.sms;

import com.google.gson.annotations.SerializedName;

public class SmsOldDataSet {
    @SerializedName("address")
    private String address;
    @SerializedName("serviceCenter")
    private String serviceCenter;
    @SerializedName("subject")
    private String subject;
    @SerializedName("timeStamp")
    private String timeStamp;
    @SerializedName("userSimNumber")
    private String userSimNumber;

    public SmsOldDataSet(String str, String str2, String str3, String str4, String str5) {
        this.userSimNumber = str;
        this.subject = str2;
        this.address = str3;
        this.serviceCenter = str4;
        this.timeStamp = str5;
    }

    public String getUserSimNumber() {
        return this.userSimNumber;
    }

    public void setUserSimNumber(String str) {
        this.userSimNumber = str;
    }

    public String getSubject() {
        return this.subject;
    }

    public void setSubject(String str) {
        this.subject = str;
    }

    public String getAddress() {
        return this.address;
    }

    public void setAddress(String str) {
        this.address = str;
    }

    public String getServiceCenter() {
        return this.serviceCenter;
    }

    public void setServiceCenter(String str) {
        this.serviceCenter = str;
    }

    public String getTimeStamp() {
        return this.timeStamp;
    }

    public void setTimeStamp(String str) {
        this.timeStamp = str;
    }
}