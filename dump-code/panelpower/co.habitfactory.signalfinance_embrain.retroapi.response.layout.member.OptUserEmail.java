package co.habitfactory.signalfinance_embrain.retroapi.response.layout.member;

import co.habitfactory.signalfinance_embrain.retroapi.response.OptResultDataset;
import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;

public class OptUserEmail extends OptResultDataset {
    @SerializedName("emailList")
    private ArrayList<UserEmailDataset> emailList;

    public OptUserEmail(String str, String str2) {
        super(str, str2);
    }

    public ArrayList<UserEmailDataset> getEmailList() {
        return this.emailList;
    }

    public void setEmailList(ArrayList<UserEmailDataset> arrayList) {
        this.emailList = arrayList;
    }
}