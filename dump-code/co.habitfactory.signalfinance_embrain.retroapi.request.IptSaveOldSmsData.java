package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;

public class IptSaveOldSmsData extends IptCommon {
    @SerializedName("oldList")
    private ArrayList<SmsOldDataSet> arrList;

    public IptSaveOldSmsData(String str, ArrayList<SmsOldDataSet> arrayList) {
        super(str);
        this.arrList = arrayList;
    }

    public ArrayList<SmsOldDataSet> getArrList() {
        return this.arrList;
    }

    public void setArrList(ArrayList<SmsOldDataSet> arrayList) {
        this.arrList = arrayList;
    }
}