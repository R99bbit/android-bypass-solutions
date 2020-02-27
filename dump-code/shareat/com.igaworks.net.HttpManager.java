package com.igaworks.net;

import android.content.Context;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;

public class HttpManager {
    public static final String ADBRIX_USER_NO = "user_no";
    protected static final String CFG_DOMAIN_LIVE = "https://config.ad-brix.com/";
    public static final String CHANNEL_TYPE = "channel_type";
    public static final String COMMERCE_V2_TEST = "http://adbrix-commerce-web-dev.ap-northeast-1.elasticbeanstalk.com/v1/";
    public static String CONFIG_REQUEST_URL_FOR_ADBrix = "/init.json";
    public static final String CONVERSION_HISTORY = "conversion_history";
    public static final String CONVERSION_KEY = "conversion_key";
    public static final String CONVERSION_KEY_LIST = "conversion_key_list";
    public static final String CONVERSION_RESULT = "conversion_result";
    protected static final String CPN_DOMAIN_LIVE_V1 = "https://campaign.ad-brix.com/v1/";
    protected static final String CRS_DOMAIN_LIVE = "https://igawcrashlytics.ad-brix.com/api/v1.0/";
    protected static final String CVR_DOMAIN_LIVE_V1 = "https://cvr.ad-brix.com/v1/";
    public static final String DATA = "Data";
    public static final String DEEPLINK = "deeplink";
    public static final String DEEPLINK_DOMAIN_LIVE = "https://apiab4c.ad-brix.com/v1/";
    public static final int DEMOGRAPHIC_CALLBACK = 2;
    public static final String INSTALL_DATETIME = "install_datetime";
    public static final String LAST_REFERRAL_DATA = "last_referral_data";
    public static final String LAST_REFERRAL_DATETIME = "last_referral_datetime";
    public static final String LAST_REFERRAL_KEY = "last_referral_key";
    public static final String POSTBACK_ENGAGEMENT_DATETIME = "reengagement_datetime";
    public static final String POSTBACK_REENGAGEMENT_DATA = "reengagement_data";
    public static final String POSTBACK_REFERRER_DATA = "referral_data";
    public static final String REENGAGEMENT_CONVERSION_KEY = "reengagement_conversion_key";
    public static final String REFERRALKEY = "referralKey";
    public static final int REFERRER_CALLBACK = 5;
    protected static final String REF_DOMAIN_LIVE_V1 = "https://ref.ad-brix.com/v1/";
    public static final String REF_USN = "refusn";
    public static final String RESULT = "Result";
    public static final String RESULT_CODE = "result_code";
    public static final String RESULT_MSG = "result_msg";
    public static final String SERVER_BASE_TIME = "BaseTime";
    public static final String SHARD_NO = "shard_no";
    public static final String SUBREFERRALKEY = "subreferralKey";
    public static final String TOAST_MSG = "toast_msg";
    public static final int TRACKING_CALLBACK = 0;
    protected static final String TRK_DOMAIN_LIVE_V1 = "https://tracking.ad-brix.com/v1/";
    public static final String WAITING_TIME = "waiting_time";
    public static String cfg_domain = CFG_DOMAIN_LIVE;
    public static String cpn_domain = CPN_DOMAIN_LIVE_V1;
    public static String crs_domain = CRS_DOMAIN_LIVE;
    public static String cvr_domain = CVR_DOMAIN_LIVE_V1;
    public static String dl_domain = DEEPLINK_DOMAIN_LIVE;
    public static String ref_domain = REF_DOMAIN_LIVE_V1;
    public static String trk_domain = TRK_DOMAIN_LIVE_V1;
    public String DEEP_LINK_CONVERSION_FOR_ADBrix = (dl_domain + "tracking/conversions");
    public String DEMOGRAPHIC_REQUEST_URL_FOR_ADBrix = (trk_domain + "tracking/SetUserDemographic");
    public String REENGAGEMENT_CONVERISON_REQ_URL_FOR_ADBRIX = (cvr_domain + "conversion/ReEngagementConversion");
    public String REFERRER_REQUEST_URL_FOR_ADBrix = (cvr_domain + "conversion/GetReferral");
    public String THIRDPARTY_CONVERSION_REQ_URL_FOR_ADBRIX = (cvr_domain + "conversion/GetAppLinkReferral");
    public String TRACKING_REQUEST_URL_FOR_ADBrix = (trk_domain + "tracking");
    public String TRACKING_REQUEST_URL_FOR_CRASHLTICS = (crs_domain + "sdkcrashevent/log");

    public static boolean isLive(Context context) {
        try {
            if (!((String) context.getPackageManager().getApplicationInfo(context.getPackageName(), 128).metaData.get("igaw_release_mode")).equals("stage")) {
                return true;
            }
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "Release Mode : stage mode", 3, true);
            return false;
        } catch (Exception e) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "Release Mode : live mode", 3, true);
            return true;
        }
    }
}