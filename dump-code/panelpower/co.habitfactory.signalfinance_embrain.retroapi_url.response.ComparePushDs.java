package co.habitfactory.signalfinance_embrain.retroapi_url.response;

import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;

public class ComparePushDs {
    @SerializedName("contains")
    private PushContentArrayDs contains;
    @SerializedName("equal")
    private PushContentArrayDs equal;
    @SerializedName("pattern")
    private ArrayList<PushPatternContentDs> pattern;
    @SerializedName("starts-with")
    private PushContentArrayDs starts_with;

    public ComparePushDs(PushContentArrayDs pushContentArrayDs, PushContentArrayDs pushContentArrayDs2, PushContentArrayDs pushContentArrayDs3, ArrayList<PushPatternContentDs> arrayList) {
        this.equal = pushContentArrayDs;
        this.starts_with = pushContentArrayDs2;
        this.contains = pushContentArrayDs3;
        this.pattern = arrayList;
    }

    public PushContentArrayDs getEqual() {
        return this.equal;
    }

    public void setEqual(PushContentArrayDs pushContentArrayDs) {
        this.equal = pushContentArrayDs;
    }

    public PushContentArrayDs getStarts_with() {
        return this.starts_with;
    }

    public void setStarts_with(PushContentArrayDs pushContentArrayDs) {
        this.starts_with = pushContentArrayDs;
    }

    public PushContentArrayDs getContains() {
        return this.contains;
    }

    public void setContains(PushContentArrayDs pushContentArrayDs) {
        this.contains = pushContentArrayDs;
    }

    public ArrayList<PushPatternContentDs> getPattern() {
        return this.pattern;
    }

    public void setPattern(ArrayList<PushPatternContentDs> arrayList) {
        this.pattern = arrayList;
    }
}