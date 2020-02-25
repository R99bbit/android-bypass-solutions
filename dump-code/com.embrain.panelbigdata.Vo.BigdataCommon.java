package com.embrain.panelbigdata.Vo;

public class BigdataCommon {
    public String OS = "Android";
    public String ad_id;
    public String app_version;
    public long execute_time = System.currentTimeMillis();
    public String model;
    public String os_version;
    public String panel_id;
    public String tel_corp;
    public String tel_std;
    public String time_zone;

    public BigdataCommon(String str) {
        this.panel_id = str;
    }
}