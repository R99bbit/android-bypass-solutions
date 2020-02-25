package co.habitfactory.signalfinance_embrain.retroapi.request.user;

import com.google.gson.annotations.SerializedName;

public class UserAppData {
    @SerializedName("apkName")
    private String apkName;
    @SerializedName("installed")
    private String installed;
    @SerializedName("lastModified")
    private String lastModified;
    @SerializedName("packageName")
    private String packageName;
    @SerializedName("reqVersion")
    private String reqVersion;
    @SerializedName("version")
    private String version;

    public UserAppData(String str, String str2, String str3, String str4, String str5, String str6) {
        this.apkName = str;
        this.packageName = str2;
        this.version = str3;
        this.reqVersion = str4;
        this.installed = str5;
        this.lastModified = str6;
    }

    public String getApkName() {
        return this.apkName;
    }

    public void setApkName(String str) {
        this.apkName = str;
    }

    public String getPackageName() {
        return this.packageName;
    }

    public void setPackageName(String str) {
        this.packageName = str;
    }

    public String getVersion() {
        return this.version;
    }

    public void setVersion(String str) {
        this.version = str;
    }

    public String getReqVersion() {
        return this.reqVersion;
    }

    public void setReqVersion(String str) {
        this.reqVersion = str;
    }

    public String getInstalled() {
        return this.installed;
    }

    public void setInstalled(String str) {
        this.installed = str;
    }

    public String getLastModified() {
        return this.lastModified;
    }

    public void setLastModified(String str) {
        this.lastModified = str;
    }
}