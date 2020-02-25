package co.habitfactory.signalfinance_embrain.retroapi.request;

import co.habitfactory.signalfinance_embrain.retroapi.request.user.UserAppData;
import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;

public class IptUserAppFilteredList {
    @SerializedName("dataChannel")
    private String dataChannel;
    @SerializedName("newList")
    private ArrayList<UserAppData> newList;
    @SerializedName("removeList")
    private ArrayList<UserAppData> removeList;
    @SerializedName("updateList")
    private ArrayList<UserAppData> updateList;
    @SerializedName("userId")
    private String userId;

    public IptUserAppFilteredList(String str, String str2, ArrayList<UserAppData> arrayList, ArrayList<UserAppData> arrayList2, ArrayList<UserAppData> arrayList3) {
        this.userId = str;
        this.dataChannel = str2;
        this.newList = arrayList;
        this.updateList = arrayList2;
        this.removeList = arrayList3;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String str) {
        this.userId = str;
    }

    public String getDataChannel() {
        return this.dataChannel;
    }

    public void setDataChannel(String str) {
        this.dataChannel = str;
    }

    public ArrayList<UserAppData> getNewList() {
        return this.newList;
    }

    public void setNewList(ArrayList<UserAppData> arrayList) {
        this.newList = arrayList;
    }

    public ArrayList<UserAppData> getUpdateList() {
        return this.updateList;
    }

    public void setUpdateList(ArrayList<UserAppData> arrayList) {
        this.updateList = arrayList;
    }

    public ArrayList<UserAppData> getRemoveList() {
        return this.removeList;
    }

    public void setRemoveList(ArrayList<UserAppData> arrayList) {
        this.removeList = arrayList;
    }
}