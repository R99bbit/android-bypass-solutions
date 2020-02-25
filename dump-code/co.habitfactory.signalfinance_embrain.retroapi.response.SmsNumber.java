package co.habitfactory.signalfinance_embrain.retroapi.response;

import com.google.gson.annotations.SerializedName;

public class SmsNumber {
    @SerializedName("number")
    private String number;
    @SerializedName("type")
    private String type;

    public SmsNumber(String str, String str2) {
        this.type = str;
        this.number = str2;
    }

    public String getType() {
        return this.type;
    }

    public void setType(String str) {
        this.type = str;
    }

    public String getNumber() {
        return this.number;
    }

    public void setNumber(String str) {
        this.number = str;
    }
}