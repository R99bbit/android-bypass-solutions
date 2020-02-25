package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptAdid {
    @SerializedName("adid")
    private String adid;
    @SerializedName("dataChannel")
    private String dataChannel;
    @SerializedName("userId")
    private String userId;

    public IptAdid(String str, String str2, String str3) {
        this.userId = str;
        this.adid = str2;
        this.dataChannel = str3;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String str) {
        this.userId = str;
    }

    public String getAdid() {
        return this.adid;
    }

    public void setAdid(String str) {
        this.adid = str;
    }

    public String getDataChannel() {
        return this.dataChannel;
    }

    public void setDataChannel(String str) {
        this.dataChannel = str;
    }
}