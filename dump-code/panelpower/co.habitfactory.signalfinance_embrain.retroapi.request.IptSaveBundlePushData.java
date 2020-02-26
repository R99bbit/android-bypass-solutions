package co.habitfactory.signalfinance_embrain.retroapi.request;

import androidx.annotation.Nullable;
import co.habitfactory.signalfinance_embrain.dataset.PushDataSet;
import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;

public class IptSaveBundlePushData extends IptCommon {
    @SerializedName("oldList")
    private ArrayList<PushDataSet> arrList;
    @SerializedName("userSimNumber")
    @Nullable
    private String userSimNumber;

    public IptSaveBundlePushData(String str, String str2, ArrayList<PushDataSet> arrayList) {
        super(str);
        this.userSimNumber = str2;
        this.arrList = arrayList;
    }

    public String getUserSimNumber() {
        return this.userSimNumber;
    }

    public void setUserSimNumber(String str) {
        this.userSimNumber = str;
    }

    public ArrayList<PushDataSet> getArrList() {
        return this.arrList;
    }

    public void setArrList(ArrayList<PushDataSet> arrayList) {
        this.arrList = arrayList;
    }
}