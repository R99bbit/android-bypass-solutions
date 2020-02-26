package com.embrain.panelpower.networks;

public class URLList {
    static final String AGREE_CALL;
    static final String AGREE_EMAIL;
    static final String AGREE_LOCATION;
    static final String AGREE_MOBILE;
    static final String AGREE_PAY;
    static final String AGREE_PUSH;
    static final String AGREE_USAGE;
    static final String ALARM_LIST;
    static final String EVENT_RECOMMEND_KAKAO_MSG;
    static final String EVENT_RECOMMEND_LINE_MSG;
    private static final boolean HABIT_DEBUG = false;
    static final String HOST = "https://www.panel.co.kr";
    static final String ID_MAPPING_HABIT;
    static final String LOGIN = "https://www.panel.co.kr/mobile/login/appLoginDesc";
    static final String MY_INFO;
    static final String REGISTED_HABIT;
    public static String SIGNAL_API_DEV = "https://sapi-dev.habitfactory.co/signal/";
    public static String SIGNAL_API_REAL = "https://sapi.habitfactory.co/signal/";
    public static String SIGNAL_EMBRAIN_DEV = "https://blue.ideaboard.co.kr:8082";
    static final String SIGNAL_EMBRAIN_HOST = SIGNAL_EMBRAIN_REAL;
    public static String SIGNAL_EMBRAIN_REAL = "https://blue.ideaboard.co.kr:1104";
    public static final String SIGNAL_URL = SIGNAL_API_REAL;
    static final String SURVEY_EXPRESS;
    static final String USER = "/user";
    static final String VERSION_CHECK;

    static String getHost() {
        return "https://www.panel.co.kr/user";
    }

    static {
        StringBuilder sb = new StringBuilder();
        sb.append(getHost());
        sb.append("/app/version/checkAppVersion");
        VERSION_CHECK = sb.toString();
        StringBuilder sb2 = new StringBuilder();
        sb2.append(getHost());
        sb2.append("/app/alarm/CheckSurveyExpress");
        SURVEY_EXPRESS = sb2.toString();
        StringBuilder sb3 = new StringBuilder();
        sb3.append(getHost());
        sb3.append("/mobile/mypage/getMyInfo");
        MY_INFO = sb3.toString();
        StringBuilder sb4 = new StringBuilder();
        sb4.append(getHost());
        sb4.append("/mobile/app/updatePushSurveyOnline");
        AGREE_PUSH = sb4.toString();
        StringBuilder sb5 = new StringBuilder();
        sb5.append(getHost());
        sb5.append("/mobile/mypage/updateEmailAgree");
        AGREE_EMAIL = sb5.toString();
        StringBuilder sb6 = new StringBuilder();
        sb6.append(getHost());
        sb6.append("/mobile/symposium/updateSmsAgree");
        AGREE_MOBILE = sb6.toString();
        StringBuilder sb7 = new StringBuilder();
        sb7.append(getHost());
        sb7.append("/mobile/symposium/updateCallAgree");
        AGREE_CALL = sb7.toString();
        StringBuilder sb8 = new StringBuilder();
        sb8.append(getHost());
        sb8.append("/mobile/app/updateLocAgree");
        AGREE_LOCATION = sb8.toString();
        StringBuilder sb9 = new StringBuilder();
        sb9.append(getHost());
        sb9.append("/mobile/app/updateInfoExt");
        AGREE_USAGE = sb9.toString();
        StringBuilder sb10 = new StringBuilder();
        sb10.append(getHost());
        sb10.append("/mobile/app/updateInfoPay");
        AGREE_PAY = sb10.toString();
        StringBuilder sb11 = new StringBuilder();
        sb11.append(getHost());
        sb11.append("/mobile/main/getAppBadgeCnt");
        ALARM_LIST = sb11.toString();
        StringBuilder sb12 = new StringBuilder();
        sb12.append(SIGNAL_EMBRAIN_HOST);
        sb12.append("/api/v1/payment/checkuser");
        REGISTED_HABIT = sb12.toString();
        StringBuilder sb13 = new StringBuilder();
        sb13.append(SIGNAL_EMBRAIN_HOST);
        sb13.append("/api/v1/payment/reguser");
        ID_MAPPING_HABIT = sb13.toString();
        StringBuilder sb14 = new StringBuilder();
        sb14.append(getHost());
        sb14.append("/event/open/appRecEventKakao");
        EVENT_RECOMMEND_KAKAO_MSG = sb14.toString();
        StringBuilder sb15 = new StringBuilder();
        sb15.append(getHost());
        sb15.append("/event/open/appRecEventLine");
        EVENT_RECOMMEND_LINE_MSG = sb15.toString();
    }
}