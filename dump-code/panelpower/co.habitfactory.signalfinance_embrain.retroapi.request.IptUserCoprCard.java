package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptUserCoprCard extends IptCommon {
    @SerializedName("includeCorpCard")
    private String includeCorpCard;

    public IptUserCoprCard(String str, String str2) {
        super(str);
        this.includeCorpCard = str2;
    }

    public String getIncludeCorpCard() {
        return this.includeCorpCard;
    }

    public void setIncludeCorpCard(String str) {
        this.includeCorpCard = str;
    }
}