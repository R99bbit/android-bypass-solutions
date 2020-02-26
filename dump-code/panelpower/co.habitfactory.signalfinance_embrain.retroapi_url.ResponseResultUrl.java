package co.habitfactory.signalfinance_embrain.retroapi_url;

import com.google.gson.annotations.SerializedName;

public class ResponseResultUrl {
    @SerializedName("exception_pattern")
    private ResponseResultRoot exception_pattern;

    public ResponseResultUrl(ResponseResultRoot responseResultRoot) {
        this.exception_pattern = responseResultRoot;
    }

    public ResponseResultRoot getException_pattern() {
        return this.exception_pattern;
    }

    public void setException_pattern(ResponseResultRoot responseResultRoot) {
        this.exception_pattern = responseResultRoot;
    }
}