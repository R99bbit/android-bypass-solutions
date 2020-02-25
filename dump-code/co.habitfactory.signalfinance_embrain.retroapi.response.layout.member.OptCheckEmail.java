package co.habitfactory.signalfinance_embrain.retroapi.response.layout.member;

import co.habitfactory.signalfinance_embrain.retroapi.response.OptResultDataset;
import com.google.gson.annotations.SerializedName;

public class OptCheckEmail extends OptResultDataset {
    @SerializedName("agreement1")
    private String agreement1;
    @SerializedName("agreement2")
    private String agreement2;
    @SerializedName("agreement3")
    private String agreement3;
    @SerializedName("agreement4")
    private String agreement4;
    @SerializedName("isMember")
    private String isMember;

    public OptCheckEmail(String str, String str2, String str3, String str4, String str5, String str6, String str7) {
        super(str, str2);
        this.isMember = str3;
        this.agreement1 = str4;
        this.agreement2 = str5;
        this.agreement3 = str6;
        this.agreement4 = str7;
    }

    public String getIsMember() {
        return this.isMember;
    }

    public void setIsMember(String str) {
        this.isMember = str;
    }

    public String getAgreement1() {
        return this.agreement1;
    }

    public void setAgreement1(String str) {
        this.agreement1 = str;
    }

    public String getAgreement2() {
        return this.agreement2;
    }

    public void setAgreement2(String str) {
        this.agreement2 = str;
    }

    public String getAgreement3() {
        return this.agreement3;
    }

    public void setAgreement3(String str) {
        this.agreement3 = str;
    }

    public String getAgreement4() {
        return this.agreement4;
    }

    public void setAgreement4(String str) {
        this.agreement4 = str;
    }
}