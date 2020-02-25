package co.habitfactory.signalfinance_embrain.retroapi.response;

import com.google.gson.annotations.SerializedName;

public class OptResultDataset {
    @SerializedName("message")
    private String message;
    @SerializedName("resultcode")
    private String resultcode;

    public OptResultDataset(String str, String str2) {
        this.resultcode = str;
        this.message = str2;
    }

    public String getResultcode() {
        return this.resultcode;
    }

    public void setResultcode(String str) {
        this.resultcode = str;
    }

    public String getMessage() {
        return this.message;
    }

    public void setMessage(String str) {
        this.message = str;
    }
}