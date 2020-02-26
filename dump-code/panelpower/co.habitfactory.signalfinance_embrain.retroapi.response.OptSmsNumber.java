package co.habitfactory.signalfinance_embrain.retroapi.response;

import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;

public class OptSmsNumber extends OptResultDataset {
    @SerializedName("numList")
    private ArrayList<SmsNumber> numList;

    public OptSmsNumber(String str, String str2, ArrayList<SmsNumber> arrayList) {
        super(str, str2);
        this.numList = arrayList;
    }

    public ArrayList<SmsNumber> getNumList() {
        return this.numList;
    }

    public void setNumList(ArrayList<SmsNumber> arrayList) {
        this.numList = arrayList;
    }
}