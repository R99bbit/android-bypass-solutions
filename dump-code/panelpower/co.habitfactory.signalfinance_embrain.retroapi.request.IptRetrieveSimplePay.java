package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptRetrieveSimplePay extends IptCommon {
    @SerializedName("companyCode")
    private String companyCode;
    @SerializedName("paymentType")
    private String paymentType;
    @SerializedName("regMonth")
    private String regMonth;

    public IptRetrieveSimplePay(String str, String str2, String str3, String str4) {
        super(str);
        this.regMonth = str2;
        this.companyCode = str3;
        this.paymentType = str4;
    }

    public String getRegMonth() {
        return this.regMonth;
    }

    public void setRegMonth(String str) {
        this.regMonth = str;
    }

    public String getCompanyCode() {
        return this.companyCode;
    }

    public void setCompanyCode(String str) {
        this.companyCode = str;
    }

    public String getPaymentType() {
        return this.paymentType;
    }

    public void setPaymentType(String str) {
        this.paymentType = str;
    }
}