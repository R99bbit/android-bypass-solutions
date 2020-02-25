package co.habitfactory.signalfinance_embrain.retroapi_url.response;

import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;

public class CompareSmsDs {
    @SerializedName("contains")
    private ArrayList<String> contains;
    @SerializedName("equal")
    private ArrayList<String> equal;
    @SerializedName("pattern")
    private ArrayList<String> pattern;
    @SerializedName("starts-with")
    private ArrayList<String> starts_with;

    public CompareSmsDs(ArrayList<String> arrayList, ArrayList<String> arrayList2, ArrayList<String> arrayList3, ArrayList<String> arrayList4) {
        this.equal = arrayList;
        this.starts_with = arrayList2;
        this.contains = arrayList3;
        this.pattern = arrayList4;
    }

    public ArrayList<String> getEqual() {
        return this.equal;
    }

    public void setEqual(ArrayList<String> arrayList) {
        this.equal = arrayList;
    }

    public ArrayList<String> getStarts_with() {
        return this.starts_with;
    }

    public void setStarts_with(ArrayList<String> arrayList) {
        this.starts_with = arrayList;
    }

    public ArrayList<String> getContains() {
        return this.contains;
    }

    public void setContains(ArrayList<String> arrayList) {
        this.contains = arrayList;
    }

    public ArrayList<String> getPattern() {
        return this.pattern;
    }

    public void setPattern(ArrayList<String> arrayList) {
        this.pattern = arrayList;
    }
}