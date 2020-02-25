package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptMobilePhone {
    @SerializedName("mobilePhone")
    private String mobilePhone;

    public IptMobilePhone(String str) {
        this.mobilePhone = str;
    }

    public String getMobilePhone() {
        return this.mobilePhone;
    }

    public void setMobilePhone(String str) {
        this.mobilePhone = str;
    }
}