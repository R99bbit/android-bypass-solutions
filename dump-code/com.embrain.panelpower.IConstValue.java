package com.embrain.panelpower;

import co.habitfactory.signalfinance_embrain.comm.ResultCode;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;

public interface IConstValue {
    public static final String ALIAS_MTS1 = "5938191868";
    public static final String ALIAS_MTS2 = "0992539959";
    public static final String BEACON_APIKEY = "iiQBV9511S44B8VWd2650b0m21D469ib";
    public static final String BEACON_URL = "https://beacon.panel.co.kr";
    public static final String DATABASE_NAME_NEW = "panelpower_new.db";
    public static final int DATABASE_VERSION_NEW = 2;
    public static final String DETAIL_ID = "detailId";
    public static final int FIND_IPIN_WEB_REQUEST = 2288;
    public static final int FIND_IPIN_WEB_RESULT_FAIL = 2291;
    public static final int FIND_IPIN_WEB_RESULT_SUCCESS = 2290;
    public static final String INDEX = "index";
    public static final int JOIN_IPIN_WEB_PARENTS_REQUEST = 2222;
    public static final int JOIN_IPIN_WEB_REQUEST = 2211;
    public static final int JOIN_IPIN_WEB_RESULT_FAIL = 2234;
    public static final int JOIN_IPIN_WEB_RESULT_SUCCESS = 2233;
    public static final int JOIN_MOBILE_WEB_REQUEST = 3311;
    public static final int JOIN_MOBILE_WEB_RESULT_FAIL = 3334;
    public static final int JOIN_MOBILE_WEB_RESULT_SUCCESS = 3333;
    public static final int JOIN_TYPE_IPIN = 1000;
    public static final int JOIN_TYPE_IPIN_KID = 1002;
    public static final int JOIN_TYPE_MOBILE = 1001;
    public static final int JOIN_TYPE_MOBILE_KID = 1003;
    public static final String POST_URL = "post_url";
    public static final int REFRESH = 55555;
    public static final int ROUGH_MAP_SEND_SMS = 3399;
    public static final int SERIAL_NUMBER = 12290507;
    public static final int SERIAL_NUMBER_NEW = 1381228;
    public static final int SHARE_REQ_CODE = 4015;
    public static final String SURVEY_ONLINE_URL = "http://s.panel.co.kr/?a=";
    public static final String SURVEY_ONLINE_URL_PC = "http://survey.panel.co.kr/survey_home_check.asp?surveyidAlias=";
    public static final String SURVEY_TYPE_OFFLINE = "SurveyOffline";
    public static final String SURVEY_TYPE_ONLINE = "SurveyOnline";
    public static final int TIMEOUT = 10000;
    public static final int USER_INFO_IPIN_WEB_REQUEST = 2255;
    public static final int USER_INFO_IPIN_WEB_RESULT_FAIL = 2277;
    public static final int USER_INFO_IPIN_WEB_RESULT_SUCCESS = 2266;
    public static final String clientId = "embrain";
    public static final String clientSecret = "embrain2308";
    public static final String echo_code = "embrain_loplat_dev";

    public interface AppBannerConst {
        public static final String PATH_MENU_TP_EVENT = "E";
        public static final String PATH_MENU_TP_FUN = "F";
        public static final String PATH_MENU_TP_JOIN = "J";
        public static final String PATH_MENU_TP_NOTICE = "N";
        public static final String PATH_MENU_TP_SURVEY = "S";
        public static final String PATH_TP_APP = "A";
        public static final String PATH_TP_URL = "U";
    }

    public interface BankConst {
        public static final String[] BANK_CODE = {"04", "20", "88", ResultCode.CODE_81, "03", "23", "27", SavedMoney.GIVE_TP_SURVEY, "12", "71", "45", ResultCode.CODE_31, ResultCode.CODE_32, "34", "39", "37", "35", "07", "48", "02", "89", "90"};
        public static final String[] BANK_TITLE = {"KB\uad6d\ubbfc", "\uc6b0\ub9ac", "\uc2e0\ud55c", "KEB\ud558\ub098", "IBK\uae30\uc5c5", "SC\uc81c\uc77c", "\ud55c\uad6d\uc528\ud2f0", "\ub18d\ud611\uc911\uc559\ud68c", "\ub2e8\uc704\ub18d\ud611", "\uc6b0\uccb4\uad6d", "\uc0c8\ub9c8\uc744\uae08\uace0", "\ub300\uad6c", "\ubd80\uc0b0", "\uad11\uc8fc", "\uacbd\ub0a8", "\uc804\ubd81", "\uc81c\uc8fc", "\uc218\ud611", "\uc2e0\ud611", "KDB\uc0b0\uc5c5", "\ucf00\uc774\ubc45\ud06c", "\uce74\uce74\uc624\ubc45\ud06c"};
    }

    public interface CertConst {
        public static final String CELL_CORP_KT = "2";
        public static final String CELL_CORP_LGT = "3";
        public static final String CELL_CORP_MVNO = "4";
        public static final String CELL_CORP_SKT = "1";
        public static final String GENDER_FEMALE = "0";
        public static final String GENDER_MALE = "1";
        public static final String NATIONAL_INFO_FOREIGN = "1";
        public static final String NATIONAL_INFO_LOCAL = "0";
        public static final String RETURN_PATH = "/cert";
        public static final String SUB_TYPE_CHILDREN = "C";
        public static final String SUB_TYPE_NORMAL = "N";
        public static final String SUB_TYPE_PARENT = "P";
        public static final String TYPE_CHECKPLUS = "checkplus";
        public static final String TYPE_IPIN = "ipin";
    }

    public interface DatabaseConst {
        public static final String COL_BEACON_LINK_URL = "beacon_link_url";
        public static final String COL_CATEGORY_CATEGORY = "category";
        public static final String COL_CATEGORY_INDEX = "idx";
        public static final String COL_CATEGORY_PACKAGE = "appPackageName";
        public static final String COL_GPS_AGREE_YN = "gps_agree_yn";
        public static final String COL_INDEX = "idx";
        public static final String COL_LAST_NOTICE = "last_notice_date";
        public static final String COL_MESSAGE = "message";
        public static final String COL_MSG_TYPE = "msg_type";
        public static final String COL_OFFLINE_ALARM_YN = "offline_alarm_yn";
        public static final String COL_ONLINE_ALARM_YN = "alarm_yn";
        public static final String COL_PERMISSION_YN = "permission_yn";
        public static final String COL_RCV_DATE = "rcv_date";
        public static final String COL_READ_COUNT = "read_count";
        public static final String COL_REFPK = "refPk";
        public static final String COL_SPLASH_YN = "splash_yn";
    }

    public interface EventConst {
        public static final String EVENT_COMMENT_VIEW_TP_CD_CLOSE = "G";
        public static final String EVENT_COMMENT_VIEW_TP_CD_OPEN = "M";
        public static final String EVENT_TP_CD_COMMENT = "C";
        public static final String EVENT_TP_CD_INVITE = "V";
        public static final String EVENT_TP_CD_JOIN = "J";
        public static final String EVENT_TP_CD_ROCK = "R";
        public static final String EVENT_TP_CD_SURVEY = "S";
    }

    public interface FaqConst {
        public static final String[] RANK_TP_CD = {"A", "J", "S", "P", "", ""};
        public static final String[] TP_CD = {"", "J", "S", "M", "E", "X"};
    }

    public interface FragmentTag {
        public static final String BANNER_CONSUME = "Banner_consume";
        public static final String CHANGE_PW = "PwChange";
        public static final String CUSTOMER_FAQ = "FAQ";
        public static final String CUSTOMER_NOTICE = "Notice";
        public static final String CUSTOMER_NOTICE_DETAIL = "NoticeDetail";
        public static final String CUSTOMER_NOTICE_LIST = "NoticeList";
        public static final String CUSTOMER_QNA = "QNA";
        public static final String CUSTOMER_QNA_LIST = "QnAList";
        public static final String CUSTOMER_QNA_WRITE = "QnAWrite";
        public static final String DONATION = "Donation";
        public static final String DONATION_STORY_DETAIL = "DonatinoStoryDetail";
        public static final String DONATION_THANK_LETTER = "DonationThankLetter";
        public static final String EVENT_DETAIL = "EventDetail";
        public static final String EVENT_LIST = "EventList";
        public static final String EVENT_OPEN_COMMENT = "EventOpenComment";
        public static final String EVENT_OPEN_NORMAL = "EventOpenNormal";
        public static final String EVENT_RECOMMEND_CHECK = "EventRecommendCheck";
        public static final String EVENT_RECOMMEND_EMAIL = "EventRecommendEmail";
        public static final String EVENT_RECOMMEND_URL = "EventRecommendUrl";
        public static final String EVENT_RECOMND_CHECK_YET = "EventRecomndCheckYet";
        public static final String FIND = "Find";
        public static final String FIND_IPIN = "FindIpin";
        public static final String FIND_RESULT_ID = "FindResultID";
        public static final String FIND_RESULT_PW = "FindResultPW";
        public static final String FUN_DETAIL = "FunDetail";
        public static final String FUN_LIST = "FunList";
        public static final String GUIDE_JOIN_WEB = "GuideJoinWeb";
        public static final String GUIDE_MONEY_WEB = "GuideMoneyWeb";
        public static final String INFORMATION = "Information";
        public static final String JOIN = "Join";
        public static final String JOIN_AUTH_IPIN = "JoinIpin";
        public static final String JOIN_AUTH_IPIN_WEB = "JoinIpinWeb";
        public static final String JOIN_AUTH_MOBILE = "JoinMobile";
        public static final String JOIN_FINISH = "JoinFinish";
        public static final String JOIN_JOIN_INPUT_DATA1 = "JoinInputData1";
        public static final String JOIN_JOIN_INPUT_DATA2 = "JoinInputData2";
        public static final String JOIN_JOIN_INPUT_DATA3 = "JoinInputData3";
        public static final String JOIN_JOIN_INPUT_DATA4 = "JoinInputData4";
        public static final String JOIN_KID = "JoinKid";
        public static final String JOIN_PARENTS = "JoinParents";
        public static final String JOIN_TERM = "JoinTerm";
        public static final String LOGIN = "Login";
        public static final String MAIN = "Main";
        public static final String MEMBER_LEAVE = "MembersLeave";
        public static final String MESSAGE = "Message";
        public static final String MYPAGE = "MyPage";
        public static final String REQUEST_SURVEY_OFFLINE = "RequestSurveyOffline";
        public static final String REQUEST_SURVEY_OFFLINE_DETAIL = "RequestSurveyOfflineDetail";
        public static final String REQUEST_SURVEY_ONLINE = "RequestSurveyOnline";
        public static final String REQUEST_SURVEY_ONLINE_EVENT = "RequestSurveyOnlineEvent";
        public static final String ROUGH_MAP = "RoughMap";
        public static final String SAVED_MONEY_DETAIL = "SavedMoneyDetail";
        public static final String SAVED_MONEY_LIST = "SavedMoneyList";
        public static final String SAVED_MONEY_REQUEST = "SavedMoneyRequest";
        public static final String SAVED_MONEY_REQUEST_CHECK_PW = "RequestPWCheck";
        public static final String SAVED_MONEY_REQUEST_DETAIL = "SavedMoneyRequestDetail";
        public static final String SAVED_MONEY_REQUEST_SELECT = "SavedMoneyRequestSelectType";
        public static final String SETTING = "Setting";
        public static final String SETTING_CONSUME = "Setting_consume";
        public static final String SETTING_CONSUME_DT1 = "Setting_consume_detail1";
        public static final String SURVEY_DETAIL = "SurveyDetailOffline";
        public static final String SURVEY_FINISH = "SurveyFinish";
        public static final String SURVEY_LIST = "SurveyList";
        public static final String SURVEY_LIST_OFFLINE = "SurveyListOffline";
        public static final String SURVEY_LIST_ONLINE = "SurveyListOnline";
        public static final String SURVEY_OFFLINE_LOGIN_CHECK = "SurveyOfflineLoginCheck";
        public static final String SURVEY_OFFLINE_REQUEST_CONFIRM = "SurveyOfflineRequestConfirm";
        public static final String SURVEY_OFFLINE_REQUEST_GROUP = "SurveyOfflineRequestGroup";
        public static final String SURVEY_OFFLINE_REQUEST_QUESTION = "SurveyOfflineRequestQuestion";
        public static final String SURVEY_WEB = "SurveyWeb";
        public static final String TERMS_PANEL = "TermsPanel";
        public static final String TERMS_PRIVACY = "TermsPrivacy";
        public static final String TERMS_USES = "TermsUses";
        public static final String USER_INFO_EMAIL = "UserInfoEmail";
        public static final String WEB_LINK = "WebLink";
    }

    public interface JobConst {
        public static final String[] JOB_CODE = {"01", "02", "03", "04", "06", "07", "08", "09", SavedMoney.GIVE_TP_GIFT_CARD_MOBILE, SavedMoney.GIVE_TP_SURVEY, "13", "14", SignalLibConsts.MISSED_DATA_BEFORE_DAYTIME, "12"};
        public static final String[] JOB_TITLE = {"\uc804\ubb38\uc9c1", "\uacbd\uc601\uc9c1", "\uc0ac\ubb34\uc9c1", "\uc11c\ube44\uc2a4/\uc601\uc5c5/\ud310\ub9e4\uc9c1", "\uc0dd\uc0b0/\uae30\uc220\uc9c1/\ub178\ubb34\uc9c1", "\uad50\uc0ac/\ud559\uc6d0\uac15\uc0ac", "\uacf5\ubb34\uc6d0(\uacf5\uae30\uc5c5 \ud3ec\ud568)", "\ud559\uc0dd", "\uc804\uc5c5\uc8fc\ubd80", "\ub18d/\uc784/\uc5b4\uc5c5", "\uc790\uc601\uc5c5", "\uc790\uc720\uc9c1/\ud504\ub9ac\ub79c\uc11c", "\ubb34\uc9c1", "\uae30\ud0c0"};
    }

    public interface JoinConst {
        public static final String JOIN_TYPE_IPIN = "ipin";
        public static final String JOIN_TYPE_MOBILE = "mobile";
    }

    public interface LocationConst {
        public static final String LOC_NM_FIRST = "\ubcf8\uad00";
        public static final String LOC_NM_SECOND = "\ubcc4\uad00";
        public static final String LOC_NO_FIRST = "1";
        public static final String LOC_NO_SECOND = "2";
        public static final String LOC_URL_FIRST = "\uc5ed\uc0bc\ub3d9 \uc5e0\ube0c\ub808\uc778 \ubcf8\uc0ac (\uac15\ub0a8\uc5ed \ub3c4\ubcf4 10\ubd84)";
        public static final String LOC_URL_SECOND = "\uc2e0\uc0ac\ub3d9 \uc5e0\ube0c\ub808\uc778 \ubcc4\uad00 (\uc555\uad6c\uc815\uc5ed \ub3c4\ubcf4 12\ubd84)";
        public static final String MSG_TP_MMS = "M";
        public static final String MSG_TP_SMS = "S";
    }

    public interface NoticeConst {
        public static final String NOTICE_TP_EVENT = "E";
        public static final String NOTICE_TP_MONEY = "M";
        public static final String NOTICE_TP_NORMAL = "N";
        public static final String NOTICE_TP_SURVEY = "S";
        public static final String USE_TP_ALL = "ALL";
        public static final String USE_TP_APP = "APP";
        public static final String USE_TP_NONE = "NON";
        public static final String USE_TP_WEB = "WEB";
    }

    public interface Parameter {
        public static final String EXIST = "exist";
        public static final String NOT_EXIST = "not-exist";
        public static final String RESULT = "result";
        public static final String SEARCH_CONDITION_CONTENT = "cont";
        public static final String SEARCH_CONDITION_CREATER = "creNm";
        public static final String SEARCH_CONDITION_TITLE = "title";
        public static final String SUCCESS = "success";
    }

    public interface PushConst {
        public static final String PUSH_SENDER_ID = "670967102634";
        public static final String PUSH_TYPE_ANOTHER = "another";
        public static final String PUSH_TYPE_BEACON = "beacon";
        public static final String PUSH_TYPE_EVENT = "event";
        public static final String PUSH_TYPE_FUN = "fun";
        public static final String PUSH_TYPE_MAIN = "main";
        public static final String PUSH_TYPE_NOTICE = "notice";
        public static final String PUSH_TYPE_SURVEY_OFFLINE = "join";
        public static final String PUSH_TYPE_SURVEY_ONLINE = "josa";
    }

    public interface QnaConst {
        public static final String[] TP_CD = {"J", "S", "M", "E", "X"};
    }

    public interface RegexConst {
        public static final String CELL_NO = "^\\d{3}\\-\\d{3,4}\\-\\d{4}$";
        public static final String EMAIL = "^[0-9a-zA-Z]([\\-.\\w]*[0-9a-zA-Z\\-_+])*@([0-9a-zA-Z][\\-\\w]*[0-9a-zA-Z]\\.)+[a-zA-Z]{2,9}$";
        public static final String NUMBER = "^[0-9]{10,30}$";
        public static final String PHONE_NO = "^\\d{2,3}\\-\\d{3,4}\\-\\d{4}$";
        public static final String USER_ID = "^(?=.*[a-z])(?=.*[0-9]).{4,12}$";
        public static final String USER_PW = "^(?=.*[A-Za-z])(?=.*[!@#$%^*+=-_0-9]).{10,}$";
    }

    public interface SavedMoney {
        public static final String GIVE_STATUS_ERROR = "1";
        public static final String GIVE_STATUS_OK = "0";
        public static final String GIVE_STATUS_WAIT = "2";
        public static final String GIVE_TP_DONATE = "2";
        public static final String GIVE_TP_GIFT_CARD_MOBILE = "10";
        public static final String GIVE_TP_GIFT_CARD_ONLINE = "8";
        public static final String GIVE_TP_MONEY = "0";
        public static final String GIVE_TP_SURVEY = "11";
        public static final String GIVE_TP_TELCOIN = "5";
        public static final String[] PAYBACK_TITLE = {"\ud604\uae08\uc774\uccb4", "\uc628\ub77c\uc778\ubb38\ud654\uc0c1\ud488\uad8c", "\ubaa8\ubc14\uc77c\ubb38\ud654\uc0c1\ud488\uad8c", "\ud154\ucf54\uc778", "\uae30\ubd80"};
        public static final String[] PAYBACK_TP_CD = {"0", GIVE_TP_GIFT_CARD_ONLINE, GIVE_TP_GIFT_CARD_MOBILE, GIVE_TP_TELCOIN, "2"};
        public static final String[] PAYBACK_VALUE_TEXT = {"\ud604\uae08\uc774\uccb4", "\uc628\ub77c\uc778\uc0c1\ud488\uad8c", "\ubaa8\ubc14\uc77c\uc0c1\ud488\uad8c", "\ud154\ucf54\uc778"};
    }

    public interface SurveyOfflineConst {
        public static final String INV_PAY_TP_DIFFERENT = "D";
        public static final String INV_PAY_TP_EQUAL = "E";
        public static final String INV_PAY_TP_NONE = "N";
        public static final String INV_TP_EMAIL = "E";
        public static final String INV_TP_SMS = "M";
        public static final String RES_PAY_TP_DIFFERENT = "D";
        public static final String RES_PAY_TP_EQUAL = "E";
        public static final String SRV_STAT_CD_CLOSE = "C";
        public static final String SRV_STAT_CD_OPEN = "O";
        public static final String SRV_STAT_CD_PAUSE = "P";
    }

    public interface SurveyOnlineConst {
        public static final String SRV_STATE_JOIN = "C";
        public static final String SRV_STATE_TRIAL = "T";
        public static final String SRV_TP_ALL = "2";
        public static final String SRV_TP_MOBILE = "1";
        public static final String SRV_TP_PC = "0";
    }

    public interface TermsConst {
        public static final String TERMS_TP_CD_PRIVACY = "P";
        public static final String TERMS_TP_CD_USE = "A";
    }

    public interface UserConst {
        public static final String APP_LOGING_ANDROID = "A";
        public static final String GENDER_FEMALE = "2";
        public static final String GENDER_MALE = "1";
        public static final String GENDER_NOT = "-1";
        public static final String GRADE_ACTIVE = "1";
        public static final String GRADE_DORMANCY = "4";
        public static final String GRADE_INACTIVE = "3";
        public static final String GRADE_SEMI_ACTIVE = "2";
        public static final String MARRIAGE_DIVORCE = "03";
        public static final String MARRIAGE_MARRIED = "01";
        public static final String MARRIAGE_SINGLE = "02";
        public static final String MEM_SECTION_MEMBER = "M";
        public static final String MEM_SECTION_NOT_AUTH_EMAIL = "E";
        public static final String MEM_SECTION_PHONE = "P";
        public static final String MEM_SECTION_TEMP = "T";
    }
}