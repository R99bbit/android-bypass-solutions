package co.habitfactory.signalfinance.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptUserHash {
    @SerializedName("userHash")
    private String userHash;
    @SerializedName("userId")
    private String userId;

    public IptUserHash(String str, String str2) {
        this.userId = str;
        this.userHash = str2;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String str) {
        this.userId = str;
    }

    public String getUserHash() {
        return this.userHash;
    }

    public void setUserHash(String str) {
        this.userHash = str;
    }
}