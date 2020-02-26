package com.embrain.panelpower;

import com.embrain.panelbigdata.EmBigDataManager;
import com.embrain.panelbigdata.EmBigdataApplication;
import com.embrain.panelpower.utils.PanelPreferenceUtils;
import org.acra.ACRA;
import org.acra.ReportingInteractionMode;
import org.acra.annotation.ReportsCrashes;

@ReportsCrashes(formKey = "", mailTo = "macromillembrain@gmail.com", mode = ReportingInteractionMode.DIALOG, resDialogIcon = 17301659, resDialogOkToast = 2131624016, resDialogText = 2131624017, resDialogTitle = 2131623963, resToastText = 2131624018)
public class PanelApplication extends EmBigdataApplication {
    public static String EVENT_RECOMMEND_SHARE_BASE = "https://www.panel.co.kr";
    public static final String SERVICE_URL = "https://www.panel.co.kr";
    public static final String URL_ACCESS_TERMS = "https://www.panel.co.kr/user/footer/access-terms";
    public static final String URL_DIRECTION = "https://www.panel.co.kr/mobile/setting/location.do";
    public static final String URL_DIRECTION_LINK = "https://www.panel.co.kr/user/footer/location";
    public static final String URL_INFO_PAY = "https://www.panel.co.kr/user/habit/info";
    public static final String URL_INFO_USAGE = "https://www.panel.co.kr/user/admit/info";
    public static final String URL_MAP_DAUM_BRANCH = "http://m.map.daum.net/?urlX=506839&urlY=1117207&q=\uc11c\uc6b8+\uac15\ub0a8\uad6c+\ub17c\ud604\ub85c152\uae38+34\"";
    public static final String URL_MAP_DAUM_HOME = "https://m.map.kakao.com/actions/searchView?urlX=506894&urlY=1108922&q=\uc11c\uc6b8+\uac15\ub0a8\uad6c+\uac15\ub0a8\ub300\ub85c+318+#!/MOPUUQ,QNNUUOL/map/place";
    public static final String URL_MAP_GOOGLE_BRANCH = "https://www.google.co.kr/maps/place/\uc11c\uc6b8\ud2b9\ubcc4\uc2dc+\uac15\ub0a8\uad6c+\ub17c\ud604\ub85c152\uae38+34/@37.521137,127.0299549,17z/data=!4m2!3m1!1s0x357ca38d0c3ac551:0xb08911436c763c64";
    public static final String URL_MAP_GOOGLE_HOME = "https://www.google.co.kr/maps/place/\uc11c\uc6b8\ud2b9\ubcc4\uc2dc+\uac15\ub0a8\uad6c+\uac15\ub0a8\ub300\ub85c+318/@37.4913391,127.0297637,18z/data=!4m2!3m1!1s0x357ca14fd9ad3297:0x4a0160a318b8e6d";
    public static final String URL_MAP_NAVER_BRANCH = "http://m.map.naver.com/?dlevel=12&lat=37.5214396&lng=127.0309700&query=7ISc7Jq47Yq567OE7IucIOqwleuCqOq1rCDrhbztmITroZwxNTLquLggMzQ%3D&type=ADDRESS&tab=1&enc=b64#/map";
    public static final String URL_MAP_NAVER_HOME = "http://m.map.naver.com/?dlevel=12&lat=37.4915804&lng=127.0311893&query=7ISc7Jq47Yq567OE7IucIOqwleuCqOq1rCDqsJXrgqjrjIDroZwgMzE4&type=ADDRESS&tab=1&enc=b64#/map";
    public static final String URL_PRIVACY_POLICY = "https://www.panel.co.kr/user/footer/privacy-policy";
    public static final String URL_ROUGH_MAP = "https://www.panel.co.kr/user/img/icon/locationMap1_m.png";
    public static final String URL_SURVEY_DEFAULT = "https://s.panel.co.kr/?a=";

    public void onCreate() {
        super.onCreate();
        setContext(getApplicationContext());
        ACRA.init(this);
        EmBigDataManager.initBigdata(UserInfoManager.getInstance(getApplicationContext()).getPanelId(), PanelPreferenceUtils.getAdId(getApplicationContext()), PanelPreferenceUtils.getPushToken(getApplicationContext()));
    }
}