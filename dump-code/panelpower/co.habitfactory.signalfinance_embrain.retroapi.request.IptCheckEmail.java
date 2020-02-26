package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptCheckEmail {
    @SerializedName("email")
    private String email;

    public IptCheckEmail(String str) {
        this.email = str;
    }

    public String getEmail() {
        return this.email;
    }

    public void setEmail(String str) {
        this.email = str;
    }
}