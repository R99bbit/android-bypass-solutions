package co.habitfactory.signalfinance_embrain.retroapi.response.layout.sms;

import com.google.gson.annotations.SerializedName;

public class PushDataSet {
    @SerializedName("notiSubText")
    private String notiSubText;
    @SerializedName("notiText")
    private String notiText;
    @SerializedName("notiTitle")
    private String notiTitle;
    @SerializedName("packageNm")
    private String packageNm;
    @SerializedName("timestampMillis")
    private String timestampMillis;

    public PushDataSet(String str, String str2, String str3, String str4, String str5) {
        this.packageNm = str;
        this.notiTitle = str2;
        this.notiText = str3;
        this.notiSubText = str4;
        this.timestampMillis = str5;
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

    public String getTimestampMillis() {
        return this.timestampMillis;
    }

    public void setTimestampMillis(String str) {
        this.timestampMillis = str;
    }
}