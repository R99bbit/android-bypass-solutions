package co.habitfactory.signalfinance_embrain.retroapi.response.layout.comm;

import com.google.gson.annotations.SerializedName;

public class PushPackageName {
    @SerializedName("companyCode")
    private String companyCode;
    @SerializedName("packageName")
    private String packageName;

    public PushPackageName(String str, String str2) {
        this.packageName = str;
        this.companyCode = str2;
    }

    public String getPackageName() {
        return this.packageName;
    }

    public void setPackageName(String str) {
        this.packageName = str;
    }

    public String getCompanyCode() {
        return this.companyCode;
    }

    public void setCompanyCode(String str) {
        this.companyCode = str;
    }
}