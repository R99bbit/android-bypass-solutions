package com.embrain.panelpower.networks.vo;

import android.content.Context;
import com.embrain.panelbigdata.utils.StringUtils;
import com.embrain.panelpower.UserInfoManager;
import com.embrain.panelpower.UserInfoManager.UserInfo;
import com.embrain.panelpower.utils.PanelPreferenceUtils;
import com.embrain.panelpower.vo.DeviceInfo;

public class LoginVo extends PanelBasicRequest {
    private String adId;
    private String androidVer;
    private String appVer;
    private String captchaVal;
    private String gcmKey;
    private String handphone = "";
    private String imei = "";
    private String modelNo;
    private String reqOsTp;
    private String telComp;
    private String telStandard;
    private String userId;
    private String userPw;
    private String webAppGb;

    public static class Builder {
        private LoginVo mThis;

        public Builder(String str, String str2, String str3) {
            this.mThis = new LoginVo(str, str2, str3);
        }

        public Builder setSubinfo(Context context) {
            DeviceInfo deviceInfo = new DeviceInfo(context);
            this.mThis.setAdId(deviceInfo.adId);
            this.mThis.setModelNo(deviceInfo.modelNo);
            this.mThis.setReqOsTp(deviceInfo.reqOsTp);
            this.mThis.setTelComp(deviceInfo.telComp);
            this.mThis.setTelStandard(deviceInfo.telStandard);
            this.mThis.setAndroidVer(deviceInfo.androidVer);
            this.mThis.setAppVer(deviceInfo.appVer);
            return this;
        }

        public Builder setAdId(String str) {
            this.mThis.setAdId(str);
            return this;
        }

        public Builder setModelNo(String str) {
            this.mThis.setModelNo(str);
            return this;
        }

        public Builder setReqOsTp(String str) {
            this.mThis.setReqOsTp(str);
            return this;
        }

        public Builder setTelComp(String str) {
            this.mThis.setTelComp(str);
            return this;
        }

        public Builder setTelStandard(String str) {
            this.mThis.setTelStandard(str);
            return this;
        }

        public Builder setAndroidVer(String str) {
            this.mThis.setAndroidVer(str);
            return this;
        }

        public Builder setAppVer(String str) {
            this.mThis.setAppVer(str);
            return this;
        }

        public LoginVo build() {
            return this.mThis;
        }
    }

    public LoginVo(String str, String str2, String str3) {
        this.userId = str;
        this.userPw = str2;
        this.webAppGb = "app";
        if (StringUtils.isEmpty(str3)) {
            this.gcmKey = "";
        } else {
            this.gcmKey = str3.contains("\"") ? str3.replace("\"", "") : str3;
        }
    }

    public boolean canLogin() {
        return !StringUtils.isEmpty(this.userId) && !StringUtils.isEmpty(this.userId);
    }

    public void setModelNo(String str) {
        this.modelNo = str;
    }

    public void setReqOsTp(String str) {
        this.reqOsTp = str;
    }

    public void setTelComp(String str) {
        this.telComp = str;
    }

    public void setTelStandard(String str) {
        this.telStandard = str;
    }

    public void setAndroidVer(String str) {
        this.androidVer = str;
    }

    public void setAppVer(String str) {
        this.appVer = str;
    }

    public void setCaptchaVal(String str) {
        this.captchaVal = str;
    }

    public void setAdId(String str) {
        this.adId = str;
    }

    public String getGcmKey() {
        return this.gcmKey;
    }

    public String getUserId() {
        return this.userId;
    }

    public String getUserPw() {
        return this.userPw;
    }

    public static LoginVo getLoginInfo(Context context) {
        if (context == null) {
            return null;
        }
        UserInfo userInfo = UserInfoManager.getInstance(context).getUserInfo();
        if (userInfo == null) {
            return null;
        }
        LoginVo build = new Builder(userInfo.getUser_id(), userInfo.getUser_pw(), PanelPreferenceUtils.getPushToken(context)).setSubinfo(context).build();
        if (!build.canLogin()) {
            return null;
        }
        return build;
    }
}