package com.embrain.panelbigdata.usage;

public class ApplicationVo {
    public long firstInstallTime;
    public long lastUpdateTime;
    public String name;
    public String package_name;
    public String vendorName;
    public String versionName;

    public ApplicationVo(String str, String str2, String str3, long j, long j2, String str4) {
        this.name = str;
        this.package_name = str2;
        this.vendorName = str3;
        this.firstInstallTime = j;
        this.lastUpdateTime = j2;
        this.versionName = str4;
    }
}