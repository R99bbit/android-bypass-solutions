package co.habitfactory.signalfinance_embrain.retroapi.response.layout.member;

import co.habitfactory.signalfinance_embrain.retroapi.response.OptResultDataset;
import com.google.gson.annotations.SerializedName;

public class OptCorpCardStatus extends OptResultDataset {
    @SerializedName("corpCardStatus")
    private String corpCardStatus;

    public OptCorpCardStatus(String str, String str2, String str3) {
        super(str, str2);
        this.corpCardStatus = str3;
    }

    public String getCorpCardStatus() {
        return this.corpCardStatus;
    }

    public void setCorpCardStatus(String str) {
        this.corpCardStatus = str;
    }
}