package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptServerTime extends IptCommon {
    @SerializedName("dateBefore")
    private String dateBefore;

    public IptServerTime(String str, String str2) {
        super(str);
        this.dateBefore = str2;
    }

    public String getDateBefore() {
        return this.dateBefore;
    }

    public void setDateBefore(String str) {
        this.dateBefore = str;
    }
}