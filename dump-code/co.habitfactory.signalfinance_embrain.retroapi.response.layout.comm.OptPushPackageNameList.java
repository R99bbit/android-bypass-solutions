package co.habitfactory.signalfinance_embrain.retroapi.response.layout.comm;

import co.habitfactory.signalfinance_embrain.retroapi.response.OptResultDataset;
import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;

public class OptPushPackageNameList extends OptResultDataset {
    @SerializedName("packageList")
    private ArrayList<PushPackageName> packageList;

    public OptPushPackageNameList(String str, String str2, ArrayList<PushPackageName> arrayList) {
        super(str, str2);
        this.packageList = arrayList;
    }

    public ArrayList<PushPackageName> getPackageList() {
        return this.packageList;
    }

    public void setPackageList(ArrayList<PushPackageName> arrayList) {
        this.packageList = arrayList;
    }
}