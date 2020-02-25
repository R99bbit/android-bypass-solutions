package co.habitfactory.signalfinance_embrain.retroapi_url.response;

import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;

public class PushContentArrayDs {
    @SerializedName("big_text")
    private ArrayList<String> big_text;
    @SerializedName("sub_text")
    private ArrayList<String> sub_text;
    @SerializedName("text")
    private ArrayList<String> text;
    @SerializedName("title")
    private ArrayList<String> title;

    public PushContentArrayDs(ArrayList<String> arrayList, ArrayList<String> arrayList2, ArrayList<String> arrayList3, ArrayList<String> arrayList4) {
        this.title = arrayList;
        this.text = arrayList2;
        this.big_text = arrayList3;
        this.sub_text = arrayList4;
    }

    public ArrayList<String> getTitle() {
        return this.title;
    }

    public void setTitle(ArrayList<String> arrayList) {
        this.title = arrayList;
    }

    public ArrayList<String> getText() {
        return this.text;
    }

    public void setText(ArrayList<String> arrayList) {
        this.text = arrayList;
    }

    public ArrayList<String> getBig_text() {
        return this.big_text;
    }

    public void setBig_text(ArrayList<String> arrayList) {
        this.big_text = arrayList;
    }

    public ArrayList<String> getSub_text() {
        return this.sub_text;
    }

    public void setSub_text(ArrayList<String> arrayList) {
        this.sub_text = arrayList;
    }
}