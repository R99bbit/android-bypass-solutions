package co.habitfactory.signalfinance_embrain.retroapi.response;

import com.google.gson.annotations.SerializedName;

public class ResponseResult {
    @SerializedName("message")
    private String message;
    @SerializedName("result")
    private String result;
    @SerializedName("resultcode")
    private String resultcode;

    public String getResult() {
        return this.result;
    }

    public String getResultcode() {
        return this.resultcode;
    }

    public String getMessage() {
        return this.message;
    }

    public void setResult(String str) {
        this.result = str;
    }

    public void setResultcode(String str) {
        this.resultcode = str;
    }

    public void setMessage(String str) {
        this.message = str;
    }
}