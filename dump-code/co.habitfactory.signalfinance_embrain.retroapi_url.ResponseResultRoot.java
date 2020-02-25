package co.habitfactory.signalfinance_embrain.retroapi_url;

import co.habitfactory.signalfinance_embrain.retroapi_url.response.ComparePushDs;
import co.habitfactory.signalfinance_embrain.retroapi_url.response.CompareSmsDs;
import com.google.gson.annotations.SerializedName;

public class ResponseResultRoot {
    @SerializedName("push")
    private ComparePushDs comparePushDs;
    @SerializedName("sms")
    private CompareSmsDs compareSmsDs;

    public ResponseResultRoot(CompareSmsDs compareSmsDs2, ComparePushDs comparePushDs2) {
        this.compareSmsDs = compareSmsDs2;
        this.comparePushDs = comparePushDs2;
    }

    public CompareSmsDs getCompareSmsDs() {
        return this.compareSmsDs;
    }

    public void setCompareSmsDs(CompareSmsDs compareSmsDs2) {
        this.compareSmsDs = compareSmsDs2;
    }

    public ComparePushDs getComparePushDs() {
        return this.comparePushDs;
    }

    public void setComparePushDs(ComparePushDs comparePushDs2) {
        this.comparePushDs = comparePushDs2;
    }
}