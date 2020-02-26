package com.embrain.panelbigdata.usage;

public class ApplicationDao {
    public String app_name;
    public String app_ver;
    public long exec_time;
    public long first_install_time;
    public long last_update_time;
    public String market_package;
    public String package_name;

    public ApplicationDao(String str, String str2, String str3, long j, long j2, String str4) {
        this.app_name = str;
        this.package_name = str2;
        this.market_package = str3;
        this.first_install_time = j;
        this.last_update_time = j2;
        this.app_ver = str4;
    }

    public void setExecTime(long j) {
        this.exec_time = j;
    }

    public String getVersion_name() {
        return this.app_ver;
    }

    public String getMarket_package() {
        return this.market_package;
    }
}