package co.habitfactory.signalfinance_embrain.retroapi.response.layout.member;

import com.google.gson.annotations.SerializedName;

public class UserEmailDataset {
    @SerializedName("email")
    private String email;
    @SerializedName("loginType")
    private String loginType;

    public UserEmailDataset(String str, String str2) {
        this.email = str;
        this.loginType = str2;
    }

    public String getEmail() {
        return this.email;
    }

    public void setEmail(String str) {
        this.email = str;
    }

    public String getLoginType() {
        return this.loginType;
    }

    public void setLoginType(String str) {
        this.loginType = str;
    }
}