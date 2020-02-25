package co.habitfactory.signalfinance_embrain.retroapi_url.response;

import com.google.gson.annotations.SerializedName;

public class PushContentDs {
    @SerializedName("big_text")
    private String big_text;
    @SerializedName("sub_text")
    private String sub_text;
    @SerializedName("text")
    private String text;
    @SerializedName("title")
    private String title;

    public PushContentDs(String str, String str2, String str3, String str4) {
        this.title = str;
        this.text = str2;
        this.big_text = str3;
        this.sub_text = str4;
    }

    public String getTitle() {
        return this.title;
    }

    public void setTitle(String str) {
        this.title = str;
    }

    public String getText() {
        return this.text;
    }

    public void setText(String str) {
        this.text = str;
    }

    public String getBig_text() {
        return this.big_text;
    }

    public void setBig_text(String str) {
        this.big_text = str;
    }

    public String getSub_text() {
        return this.sub_text;
    }

    public void setSub_text(String str) {
        this.sub_text = str;
    }
}