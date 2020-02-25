package com.embrain.panelbigdata.common;

import android.content.Context;
import com.embrain.panelbigdata.Vo.BigdataCommon;
import com.embrain.panelbigdata.utils.DeviceUtils;

public class BigDataCommonVo extends BigdataCommon {
    public BigDataCommonVo(Context context, String str, String str2) {
        super(str);
        this.ad_id = str2;
        this.app_version = DeviceUtils.getAppVersion(context);
        this.model = DeviceUtils.getDeviceModel();
        this.os_version = DeviceUtils.getOSVersion();
        this.tel_corp = DeviceUtils.getTelCoperation(context);
        this.tel_std = DeviceUtils.getTelStandard(context);
        this.time_zone = DeviceUtils.getTimeZone();
    }
}