package com.embrain.panelbigdata.common;

import android.content.Context;
import com.embrain.panelbigdata.utils.DeviceUtils;

public class DeviceInfo {
    public String ad_id = "";
    public String app_ver;
    public String model;
    public String os_ver;
    public String tel_corp;
    public String tel_std;
    public String time_zone;

    public DeviceInfo(Context context) {
        this.app_ver = DeviceUtils.getAppVersion(context);
        this.model = DeviceUtils.getDeviceModel();
        this.os_ver = DeviceUtils.getOSVersion();
        this.tel_corp = DeviceUtils.getTelCoperation(context);
        this.tel_std = DeviceUtils.getTelStandard(context);
        this.time_zone = DeviceUtils.getTimeZone();
    }

    public String getAd_id() {
        return this.ad_id;
    }

    public String getApp_ver() {
        return this.app_ver;
    }

    public String getModel() {
        return this.model;
    }

    public String getOs_ver() {
        return this.os_ver;
    }

    public String getTel_corp() {
        return this.tel_corp;
    }

    public String getTel_std() {
        return this.tel_std;
    }

    public String getTime_zone() {
        return this.time_zone;
    }
}