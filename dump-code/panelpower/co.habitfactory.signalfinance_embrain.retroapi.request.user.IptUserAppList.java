package co.habitfactory.signalfinance_embrain.retroapi.request.user;

import co.habitfactory.signalfinance_embrain.retroapi.request.IptCommon;
import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;

public class IptUserAppList extends IptCommon {
    @SerializedName("appList")
    private ArrayList<UserAppData> arrList;
    @SerializedName("dataChannel")
    private String dataChannel;

    public IptUserAppList(String str, ArrayList<UserAppData> arrayList, String str2) {
        super(str);
        this.arrList = arrayList;
        this.dataChannel = str2;
    }

    public ArrayList<UserAppData> getArrList() {
        return this.arrList;
    }

    public void setArrList(ArrayList<UserAppData> arrayList) {
        this.arrList = arrayList;
    }

    public String getDataChannel() {
        return this.dataChannel;
    }

    public void setDataChannel(String str) {
        this.dataChannel = str;
    }
}