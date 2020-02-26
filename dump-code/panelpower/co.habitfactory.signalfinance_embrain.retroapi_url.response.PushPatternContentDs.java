package co.habitfactory.signalfinance_embrain.retroapi_url.response;

import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;

public class PushPatternContentDs {
    @SerializedName("package")
    private String packageNm;
    @SerializedName("pattern")
    private ArrayList<PushContentDs> pattern;

    public PushPatternContentDs(String str, ArrayList<PushContentDs> arrayList) {
        this.packageNm = str;
        this.pattern = arrayList;
    }

    public String getPackageNm() {
        return this.packageNm;
    }

    public void setPackageNm(String str) {
        this.packageNm = str;
    }

    public ArrayList<PushContentDs> getPattern() {
        return this.pattern;
    }

    public void setPattern(ArrayList<PushContentDs> arrayList) {
        this.pattern = arrayList;
    }
}