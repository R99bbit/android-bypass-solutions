package com.embrain.panelbigdata.Vo.usage;

public class UsageDao {
    public String app_name;
    public long exec_time;
    public long first_time_stamp;
    public long last_time_stamp;
    public long last_used_time_stamp;
    public String package_name;
    public long total_used_time;

    public UsageDao() {
    }

    public UsageDao(String str, long j, long j2, long j3, long j4, String str2) {
        this.package_name = str;
        this.total_used_time = j;
        this.first_time_stamp = j2;
        this.last_time_stamp = j3;
        this.last_used_time_stamp = j4;
        this.app_name = str2;
    }

    public void setExecTime(long j) {
        this.exec_time = j;
    }

    public String getPackageName() {
        return this.package_name;
    }

    public String getPackage_name() {
        return this.package_name;
    }

    public long getTotal_used_time() {
        return this.total_used_time;
    }

    public long getFirst_time_stamp() {
        return this.first_time_stamp;
    }

    public long getLast_time_stamp() {
        return this.last_time_stamp;
    }

    public long getLast_used_time_stamp() {
        return this.last_used_time_stamp;
    }
}