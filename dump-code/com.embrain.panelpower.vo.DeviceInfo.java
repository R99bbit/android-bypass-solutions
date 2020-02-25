package com.embrain.panelpower.vo;

import android.content.Context;
import com.embrain.panelbigdata.Vo.EmBasicRequest;
import com.embrain.panelbigdata.utils.DeviceUtils;
import com.embrain.panelpower.utils.PanelPreferenceUtils;
import com.kakao.util.helper.CommonProtocol;

public class DeviceInfo extends EmBasicRequest {
    public String adId;
    public String androidVer = DeviceUtils.getOSVersion();
    public String appVer;
    public String captchaVal;
    public String gcmKey;
    public String handphone;
    public String imei;
    public String modelNo;
    public String reqOsTp;
    public String telComp;
    public String telStandard;

    public DeviceInfo(Context context) {
        this.adId = PanelPreferenceUtils.getAdId(context);
        this.appVer = DeviceUtils.getAppVersion(context);
        this.captchaVal = "";
        this.handphone = "";
        this.imei = "";
        this.modelNo = DeviceUtils.getDeviceModel();
        this.reqOsTp = CommonProtocol.OS_ANDROID;
        this.telComp = DeviceUtils.getTelCoperation(context);
        this.telStandard = DeviceUtils.getTelStandard(context);
        this.gcmKey = PanelPreferenceUtils.getPushToken(context);
        if (this.gcmKey.contains("\"")) {
            this.gcmKey = this.gcmKey.replace("\"", "");
        }
    }
}