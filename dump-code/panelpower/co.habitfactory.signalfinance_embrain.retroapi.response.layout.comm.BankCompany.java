package co.habitfactory.signalfinance_embrain.retroapi.response.layout.comm;

import com.google.gson.annotations.SerializedName;

public class BankCompany {
    @SerializedName("code")
    private String code;
    @SerializedName("name")
    private String name;

    public BankCompany(String str, String str2) {
        this.code = str;
        this.name = str2;
    }

    public String getCode() {
        return this.code;
    }

    public void setCode(String str) {
        this.code = str;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String str) {
        this.name = str;
    }
}