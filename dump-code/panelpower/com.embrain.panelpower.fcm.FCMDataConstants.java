package com.embrain.panelpower.fcm;

public interface FCMDataConstants {
    public static final String DATA_ANOTHER_URL = "another_url";
    public static final String DATA_KEY_DATA_TYPE = "data_type";
    public static final String DATA_KEY_EXECUTE = "exec";
    public static final String DATA_KEY_TYPE = "type";
    public static final String DATA_MSG = "msg";
    public static final String DATA_PSID = "psid";
    public static final String DATA_PUSH_NUM = "pu_num";
    public static final String DATA_PUSH_TYPE1 = "push_type1";
    public static final String DATA_PUSH_TYPE2 = "push_type2";
    public static final String DATA_PUSH_TYPE3 = "push_type3";
    public static final String DATA_PU_IDX = "pu_idx";
    public static final String DATA_REF_PK = "ref_pk";
    public static final String VALUE_BIG_DATA_SESSION = "session";
    public static final String VALUE_BIG_DATA_STOP = "stop";
    public static final String VALUE_DATA_TYPE_ALL = "all";
    public static final String VALUE_DATA_TYPE_LOCATION = "location";
    public static final String VALUE_DATA_TYPE_USAGE = "usage";
    public static final String VALUE_TYPE_BIG_DATA = "bigdata";

    public interface PushType {
        public static final String ANOTHER = "another";
        public static final String BEACON = "beacon";
        public static final String EVENT = "event";
        public static final String FUN = "fun";
        public static final String MAIN = "main";
        public static final String NOTICE = "notice";
        public static final String SURVEY_OFFLINE = "join";
        public static final String SURVEY_ONLINE = "josa";
    }
}