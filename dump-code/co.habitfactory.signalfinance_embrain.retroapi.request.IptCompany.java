package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptCompany {
    @SerializedName("companyCode")
    private String companyCode;
    @SerializedName("userId")
    private String userId;

    public IptCompany(String str, String str2) {
        this.userId = str;
        this.companyCode = str2;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String str) {
        this.userId = str;
    }

    public String getCompanyCode() {
        return this.companyCode;
    }

    public void setCompanyCode(String str) {
        this.companyCode = str;
    }
}