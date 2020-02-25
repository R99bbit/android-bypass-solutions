package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptDashBoardRetrieveYearMonthSum extends IptCommon {
    @SerializedName("regYear")
    private String regYear;

    public IptDashBoardRetrieveYearMonthSum(String str, String str2) {
        super(str);
        this.regYear = str2;
    }

    public String getRegYear() {
        return this.regYear;
    }

    public void setRegYear(String str) {
        this.regYear = str;
    }
}