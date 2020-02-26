package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptLogIn {
    @SerializedName("adid")
    private String adid;
    @SerializedName("email")
    private String email;
    @SerializedName("isAdidChanged")
    private String isAdidChanged;
    @SerializedName("mobilePhone")
    private String mobilePhone;

    public IptLogIn(String str, String str2, String str3, String str4) {
        this.adid = str;
        this.email = str2;
        this.mobilePhone = str3;
        this.isAdidChanged = str4;
    }

    public String getAdid() {
        return this.adid;
    }

    public void setAdid(String str) {
        this.adid = str;
    }

    public String getEmail() {
        return this.email;
    }

    public void setEmail(String str) {
        this.email = str;
    }

    public String getMobilePhone() {
        return this.mobilePhone;
    }

    public void setMobilePhone(String str) {
        this.mobilePhone = str;
    }

    public String getIsAdidChanged() {
        return this.isAdidChanged;
    }

    public void setIsAdidChanged(String str) {
        this.isAdidChanged = str;
    }
}