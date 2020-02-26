package com.embrain.panelbigdata.network;

public class URLList {
    static final String BIG_DATA_SESSION;
    static final String BIG_DATA_SESSION_LISt;
    static final String GPS_STATE;
    static final String GPS_STATE_LIST;
    static final String HOST = "https://bigdata.iembrain.com:8443";
    static final String LOCATION_INFO;
    static final String PART = "/bigdata";
    static final String TOKEN_REGIST;
    static final String USAGE_INFO;
    static final String VERSION = "/v1";

    static String getHost() {
        return "https://bigdata.iembrain.com:8443/bigdata/v1";
    }

    static {
        StringBuilder sb = new StringBuilder();
        sb.append(getHost());
        sb.append("/token/regist");
        TOKEN_REGIST = sb.toString();
        StringBuilder sb2 = new StringBuilder();
        sb2.append(getHost());
        sb2.append("/session");
        BIG_DATA_SESSION = sb2.toString();
        StringBuilder sb3 = new StringBuilder();
        sb3.append(getHost());
        sb3.append("/sessionList");
        BIG_DATA_SESSION_LISt = sb3.toString();
        StringBuilder sb4 = new StringBuilder();
        sb4.append(getHost());
        sb4.append("/usage/insert");
        USAGE_INFO = sb4.toString();
        StringBuilder sb5 = new StringBuilder();
        sb5.append(getHost());
        sb5.append("/location/insert");
        LOCATION_INFO = sb5.toString();
        StringBuilder sb6 = new StringBuilder();
        sb6.append(getHost());
        sb6.append("/location/gps");
        GPS_STATE = sb6.toString();
        StringBuilder sb7 = new StringBuilder();
        sb7.append(getHost());
        sb7.append("/location/gpsList");
        GPS_STATE_LIST = sb7.toString();
    }
}