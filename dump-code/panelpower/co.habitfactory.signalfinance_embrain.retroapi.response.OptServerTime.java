package co.habitfactory.signalfinance_embrain.retroapi.response;

import com.google.gson.annotations.SerializedName;

public class OptServerTime extends OptResultDataset {
    @SerializedName("bDate")
    private String bDate;
    @SerializedName("bMillis")
    private String bMillis;
    @SerializedName("cDate")
    private String cDate;
    @SerializedName("cMillis")
    private String cMillis;
    @SerializedName("gMillis")
    private String gMillis;

    public OptServerTime(String str, String str2, String str3, String str4, String str5, String str6, String str7) {
        super(str, str2);
        this.bDate = str3;
        this.bMillis = str4;
        this.cDate = str5;
        this.cMillis = str6;
        this.gMillis = str7;
    }

    public String getbDate() {
        return this.bDate;
    }

    public void setbDate(String str) {
        this.bDate = str;
    }

    public String getbMillis() {
        return this.bMillis;
    }

    public void setbMillis(String str) {
        this.bMillis = str;
    }

    public String getcDate() {
        return this.cDate;
    }

    public void setcDate(String str) {
        this.cDate = str;
    }

    public String getcMillis() {
        return this.cMillis;
    }

    public void setcMillis(String str) {
        this.cMillis = str;
    }

    public String getgMillis() {
        return this.gMillis;
    }

    public void setgMillis(String str) {
        this.gMillis = str;
    }
}