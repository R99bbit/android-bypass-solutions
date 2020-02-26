package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptStore {
    @SerializedName("storeName")
    private String storeName;
    @SerializedName("userId")
    private String userId;

    public IptStore(String str, String str2) {
        this.userId = str;
        this.storeName = str2;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String str) {
        this.userId = str;
    }

    public String getStoreName() {
        return this.storeName;
    }

    public void setStoreName(String str) {
        this.storeName = str;
    }
}