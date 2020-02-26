package co.habitfactory.signalfinance_embrain.retroapi.response.layout.member;

import co.habitfactory.signalfinance_embrain.retroapi.response.OptResultDataset;
import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;

public class OptCardExceptionStatus extends OptResultDataset {
    @SerializedName("userCardList")
    private ArrayList<UserCardStatusDetailDataset> userCardList;

    public OptCardExceptionStatus(String str, String str2, ArrayList<UserCardStatusDetailDataset> arrayList) {
        super(str, str2);
        this.userCardList = arrayList;
    }

    public ArrayList<UserCardStatusDetailDataset> getUserCardList() {
        return this.userCardList;
    }

    public void setUserCardList(ArrayList<UserCardStatusDetailDataset> arrayList) {
        this.userCardList = arrayList;
    }
}