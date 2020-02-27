package com.igaworks.core;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.NetworkInfo.State;
import android.os.Build;
import android.os.Build.VERSION;
import android.os.Environment;
import android.os.StatFs;
import android.support.v4.media.session.PlaybackStateCompat;
import android.telephony.TelephonyManager;
import android.util.Pair;
import android.view.Display;
import android.view.WindowManager;
import com.gun0912.tedpermission.TedPermissionActivity;
import com.igaworks.core.AdvertisingIdClient.AdInfo;
import com.igaworks.dao.AbstractCPEImpressionDAO;
import com.igaworks.dao.AppImpressionDAO;
import com.igaworks.dao.CohortDAO;
import com.igaworks.dao.CoreIDDAO;
import com.igaworks.dao.LocalDemograhpicDAO;
import com.igaworks.dao.ReferralInfoDAO;
import com.igaworks.impl.CommonFrameworkFactory;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.interfaces.CommonInterface;
import com.igaworks.model.DeeplinkConversionItem;
import com.igaworks.model.DuplicationConversionKeyModel;
import com.igaworks.net.HttpManager;
import com.igaworks.util.CommonHelper;
import com.igaworks.util.IgawBase64;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TimeZone;
import java.util.regex.Pattern;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class RequestParameter {
    public static final String ACTIVITY = "activity";
    public static final String AG = "ag";
    public static final String ANDROID_ID = "android_id";
    public static final String APPKEY = "appkey";
    public static final String CARRIER = "carrier";
    public static final String COHORT_1_NAME = "custom_cohort_1";
    public static final String COHORT_2_NAME = "custom_cohort_2";
    public static final String COHORT_3_NAME = "custom_cohort_3";
    public static final String COUNTRY = "country";
    public static final String ERROR = "ERROR";
    public static final String GOOGLE_AD_ID = "google_ad_id";
    public static final String GOOGLE_AD_ID_OPT_OUT = "google_ad_id_opt_out";
    public static final String HEIGHT = "height";
    public static final String INIT_AD_ID = "initial_ad_id";
    public static final String LANGUAGE = "language";
    public static final String MARKET = "vendor";
    public static final String MC = "mc";
    public static final String MODEL = "model";
    public static final String NON_CUSTOM_NETWORK = "nonCustomNetwork";
    public static final String OS = "os";
    public static final String PLATFORM_TYPE = "ptype";
    public static final String PUDID = "pudid";
    public static final String PUID = "puid";
    public static final String REQSEQ = "reqseq";
    private static final String TAG = "ATRequestParameter";
    public static final String VERSION = "version";
    public static final String WIDTH = "width";
    public static final String WIFI_DEVICE = "wifi_device";
    public static final SimpleDateFormat df = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT);
    private static RequestParameter singletonATRequestParameter;
    private static ArrayList<Integer> tempConversionCache = new ArrayList<>();
    private static ArrayList<Integer> tempProcessedConversions = new ArrayList<>();
    private static ArrayList<Integer> tempRetainedConversionCache = new ArrayList<>();
    private String activity = null;
    private long adbrix_user_no = -1;
    /* access modifiers changed from: private */
    public AdInfo adidInfo = null;
    private String ag = "";
    private String android_id = null;
    private long app_launch_count = 0;
    private String appkey = "";
    private String carrier = "";
    private int channel_type = -1;
    private int conversion_key = -1;
    private DeviceIDManger didManager;
    /* access modifiers changed from: private */
    public String google_ad_id = "";
    /* access modifiers changed from: private */
    public boolean google_ad_id_opt_out = false;
    private String hashkey = null;
    private String install_datetime = null;
    private boolean isNewInstall = false;
    private boolean isWifiDevice = false;
    private String last_referral_data = "";
    private String last_referral_datetime = "";
    private long last_referral_key = -1;
    private long life_hour = 0;
    private String market = "";
    private String mc = null;
    private String model = "";
    private String mudid = null;
    private int nonCustomNetwork = 0;
    private String openudid = null;
    private String os = "";
    private String pudid = null;
    private String puid = null;
    private long reengagement_conversion_key = -1;
    private String reengagement_data = null;
    private String reengagement_datetime = null;
    private String referral_data = null;
    private long referral_key = -1;
    private String refusn = null;
    private int reqseq = 0;
    private boolean security_enable = false;
    private long session_no = -1;
    private int shard_no = -1;
    private String subreferral_key = null;
    private String thirdPartyID;

    private RequestParameter(final Context ctx) {
        this.didManager = DeviceIDManger.getInstance(ctx);
        try {
            new Thread(new Runnable() {
                public void run() {
                    try {
                        if (RequestParameter.this.adidInfo == null) {
                            RequestParameter.this.adidInfo = DeviceIDManger.getInstance(ctx).getAndroidADID(ctx, null);
                            if (RequestParameter.this.adidInfo != null) {
                                RequestParameter.this.google_ad_id = RequestParameter.this.adidInfo.getId();
                                RequestParameter.this.google_ad_id_opt_out = RequestParameter.this.adidInfo.isLimitAdTrackingEnabled();
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        } catch (Exception e) {
        }
    }

    public void setAppKey(String appkey2) {
        if (appkey2 == null || appkey2.equals("")) {
            this.appkey = "-1";
        }
        this.appkey = appkey2;
    }

    public void setThirdPartyID(String thirdPartyID2) {
        if (thirdPartyID2 != null && thirdPartyID2.length() > 0) {
            this.thirdPartyID = thirdPartyID2;
        }
    }

    public String getThirdPartyID() {
        return this.thirdPartyID;
    }

    public void setMc(String mc2) {
        if (mc2 == null || mc2.equals("")) {
            this.mc = "unknown";
        }
        this.mc = mc2;
    }

    public void setMarketPlace(String market2) {
        if (market2 == null || market2.equals("")) {
            market2 = "unknown";
        }
        this.market = market2;
    }

    public String getMarketPlace() {
        return this.market;
    }

    public String getModel() {
        return this.model;
    }

    public long getappLaunchCount() {
        return this.app_launch_count;
    }

    public void setReqSeq(int reqseq2) {
        this.reqseq = reqseq2;
    }

    public void setActivityName(String activity2) {
        if (activity2 == null || activity2.equals("")) {
            this.activity = "unknown";
        }
        this.activity = activity2;
    }

    public String getAppkey() {
        return this.appkey;
    }

    public String getHashkey() {
        return this.hashkey;
    }

    public void setHashkey(String hashkey2) {
        this.hashkey = hashkey2;
    }

    public static RequestParameter getATRequestParameter(Context ctx) {
        if (singletonATRequestParameter == null) {
            synchronized (RequestParameter.class) {
                if (singletonATRequestParameter == null) {
                    IgawLogger.Logging(ctx, IgawConstant.QA_TAG, "new ATRequest Parameter created", 3);
                    singletonATRequestParameter = new RequestParameter(ctx);
                }
            }
        }
        return singletonATRequestParameter;
    }

    private String checkIsNullOrEmptyAndReturnRegString(String src) {
        return (src == null || src.length() <= 0) ? "" : src;
    }

    public String getTrackingParameterForADBrix(Context context, ArrayList<String> activity_info_list, ArrayList<String> imp_info_list, String adid) throws JSONException {
        boolean adidOptOut = true;
        if (this.didManager != null) {
            AdInfo adinfo = this.didManager.getAdidInfo();
            if (adinfo != null) {
                adidOptOut = adinfo.isLimitAdTrackingEnabled();
            }
        }
        return getTrackingParameterForADBrix(context, activity_info_list, imp_info_list, null, adid, adidOptOut);
    }

    public String getTrackingParameterForADBrix(Context context, ArrayList<String> activity_info_list, ArrayList<String> imp_info_list, String adid, boolean adidOptOut) throws JSONException {
        return getTrackingParameterForADBrix(context, activity_info_list, imp_info_list, null, adid, adidOptOut);
    }

    public String getTrackingParameterForADBrix(Context context, ArrayList<String> activity_info_list, ArrayList<String> imp_info_list, ArrayList<Integer> complete_conversion_list, String adid, boolean adidOptOut) throws JSONException {
        String result = getAdbrixJSONParameter(activity_info_list, imp_info_list, complete_conversion_list, adid, adidOptOut).toString();
        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ATRequestParameter > tracking Parameter : " + result, 3);
        return result;
    }

    public String getCompleteParameterForADBrix(ArrayList<String> activity_info_list, ArrayList<String> imp_info_list, String adid, boolean adidOptOut) throws JSONException {
        String result = getAdbrixJSONParameter(activity_info_list, imp_info_list, null, adid, adidOptOut).toString();
        IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "ATRequestParameter > tracking Parameter : " + result, 3);
        return result;
    }

    public String getReferrerTrackingParameter(Context context, ArrayList<String> activity_info_list, ArrayList<String> imp_info_list, String adid, boolean adidOptOut) throws JSONException {
        String result = getAdbrixJSONParameter(activity_info_list, imp_info_list, null, null, adid, adidOptOut, true).toString();
        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ATRequestParameter > referral Parameter : " + result, 3);
        return result;
    }

    public String getReEngagementConversionTrackingParameter(Context context, JSONObject deeplink_info, String adid, boolean adidOptOut) throws JSONException {
        JSONObject rootObj = getAdbrixJSONParameter(null, null, null, adid, adidOptOut);
        if (deeplink_info != null) {
            rootObj.put("deeplink_info", deeplink_info);
        }
        String result = rootObj.toString();
        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ATRequestParameter > getDLConversionTrackingParameter : " + result, 3);
        return result;
    }

    public String getDemographicParameter() throws JSONException {
        JSONObject rootObj = new JSONObject();
        rootObj.put(PUID, checkIsNullOrEmptyAndReturnRegString(this.puid));
        if (this.google_ad_id == null) {
            this.google_ad_id = CoreIDDAO.getInstance().getGoogleAdId(CommonFrameworkImpl.getContext());
        }
        rootObj.put(GOOGLE_AD_ID, this.google_ad_id);
        JSONArray userDemoArr = new JSONArray();
        List<Pair<String, String>> demos = getDemoInfo();
        if (demos != null) {
            for (Pair<String, String> item : demos) {
                JSONObject aDemo = new JSONObject();
                aDemo.put("demo_key", item.first);
                aDemo.put("demo_value", item.second);
                userDemoArr.put(aDemo);
            }
        }
        rootObj.put("user_demo_info", userDemoArr);
        String result = rootObj.toString();
        IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "ATRequestParameter > tracking Parameter : user_demo_info" + result, 3, true);
        return result;
    }

    @SuppressLint({"NewApi"})
    public JSONObject getCrashParameter(String adid, String err, JSONArray threadInfos, String reason) throws JSONException {
        Context context = CommonFrameworkImpl.getContext();
        JSONObject rootObj = new JSONObject();
        JSONObject deviceObj = new JSONObject();
        rootObj.put("adid", adid);
        rootObj.put("os_type", "aos");
        if (VERSION.RELEASE != null && !VERSION.RELEASE.equalsIgnoreCase("")) {
            this.os = VERSION.RELEASE;
        }
        rootObj.put("os_version", "a_" + this.os);
        rootObj.put(TedPermissionActivity.EXTRA_PACKAGE_NAME, context.getPackageName());
        rootObj.put("appkey", this.appkey);
        try {
            PackageInfo pi = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            rootObj.put("app_version_name", pi.versionName);
            rootObj.put("app_version_code", pi.versionCode);
        } catch (Exception e) {
        }
        try {
            if (this.install_datetime == null || this.install_datetime.length() < 1) {
                this.install_datetime = getADBrixUserInfo_install_datetime();
            }
            if (this.install_datetime != null) {
                rootObj.put(HttpManager.INSTALL_DATETIME, this.install_datetime);
            } else {
                rootObj.put(HttpManager.INSTALL_DATETIME, "");
            }
        } catch (Exception e2) {
            rootObj.put(HttpManager.INSTALL_DATETIME, "");
        }
        rootObj.put("common_sdk_version", IgawUpdateLog.getCommonVersion());
        if (CommonFrameworkFactory.isHasAdbrixSDK) {
            rootObj.put("adbrix_sdk_version", IgawUpdateLog.VERSION);
        }
        if (CommonFrameworkFactory.isHasLiveOpsSDK) {
            try {
                Class<?> cls = Class.forName("com.igaworks.liveops.IgawLiveOpsUpdateLog");
                rootObj.put("liveops_sdk_version", cls.getDeclaredMethod("getVersion", new Class[0]).invoke(cls.newInstance(), new Object[0]));
            } catch (Exception e3) {
                e3.printStackTrace();
            }
        }
        if (CommonFrameworkFactory.isHasAdpopcornSDK) {
            try {
                Object i = Class.forName("com.igaworks.adpopcorn.cores.common.APUpdateLog").newInstance();
                rootObj.put("adpopcorn_sdk_version", i.getClass().getDeclaredField("SDK_VERSION").get(i).toString());
            } catch (Exception e4) {
                e4.printStackTrace();
            }
        }
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT2, Locale.KOREA);
        simpleDateFormat.setTimeZone(TimeZone.getTimeZone("GMT+9"));
        rootObj.put("local_kst_time", simpleDateFormat.format(new Date()));
        deviceObj.put("proximity_on", true);
        deviceObj.put("root_device", CommonHelper.findBinary("su"));
        StatFs statFs = new StatFs(Environment.getDataDirectory().getPath());
        if (VERSION.SDK_INT >= 18) {
            deviceObj.put("free_device_storage", formatSize(statFs.getAvailableBlocksLong() * statFs.getBlockSizeLong()));
        } else {
            deviceObj.put("free_device_storage", formatSize((long) (((double) statFs.getAvailableBlocks()) * ((double) statFs.getBlockSize()))));
        }
        deviceObj.put("app_in_focus", CommonFrameworkImpl.isFocusOnForCrashlytics);
        deviceObj.put("device_model", this.model);
        Runtime runtime = Runtime.getRuntime();
        deviceObj.put("free_memory", new StringBuilder(String.valueOf((runtime.maxMemory() / 1048576) - ((runtime.totalMemory() - runtime.freeMemory()) / 1048576))).append("MB").toString());
        rootObj.put("device_information", deviceObj);
        if (err != null) {
            rootObj.put("exception_log_trace", err);
        }
        if (reason != null) {
            rootObj.put("exception_reason", reason);
        }
        if (threadInfos != null) {
            rootObj.put("thread_information", threadInfos);
        }
        String result = rootObj.toString();
        IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "ATRequestParameter > array" + threadInfos.toString(), 3, true);
        IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "ATRequestParameter > crash Parameter : crash_info" + result, 3, true);
        return rootObj;
    }

    public static String formatSize(long size) {
        String suffix = null;
        if (size >= PlaybackStateCompat.ACTION_PLAY_FROM_MEDIA_ID) {
            suffix = "KB";
            size /= PlaybackStateCompat.ACTION_PLAY_FROM_MEDIA_ID;
            if (size >= PlaybackStateCompat.ACTION_PLAY_FROM_MEDIA_ID) {
                suffix = "MB";
                size /= PlaybackStateCompat.ACTION_PLAY_FROM_MEDIA_ID;
                if (size >= 1000) {
                    suffix = "GB";
                    size /= 1000;
                }
            }
        }
        StringBuilder resultBuffer = new StringBuilder(Long.toString(size));
        for (int commaOffset = resultBuffer.length() - 3; commaOffset > 0; commaOffset -= 3) {
            resultBuffer.insert(commaOffset, ',');
        }
        if (suffix != null) {
            resultBuffer.append(suffix);
        }
        return resultBuffer.toString();
    }

    private JSONObject getAdbrixJSONParameter(ArrayList<String> activity_info_list, ArrayList<String> imp_info_list, ArrayList<Integer> complete_conversion_list, String adid, boolean adidOptOut) throws JSONException {
        return getAdbrixJSONParameter(activity_info_list, imp_info_list, complete_conversion_list, null, adid, adidOptOut, false);
    }

    private JSONObject getAdbrixJSONParameter(ArrayList<String> activity_info_list, ArrayList<String> imp_info_list, ArrayList<Integer> complete_conversion_list, List<DeeplinkConversionItem> deeplink_conversions, String adid, boolean adidOptOut, boolean createSign) throws JSONException {
        Context context = CommonFrameworkImpl.getContext();
        JSONObject rootObj = new JSONObject();
        JSONArray activityInfoArr = new JSONArray();
        JSONObject adbrixUserInfoObj = new JSONObject();
        JSONArray completeConversionArr = new JSONArray();
        JSONArray conversionCacheArr = new JSONArray();
        JSONArray demoArray = new JSONArray();
        JSONObject deviceInfoObj = new JSONObject();
        JSONObject referralInfoObj = new JSONObject();
        new JSONObject();
        JSONObject userInfoObj = new JSONObject();
        JSONArray impInfoArr = new JSONArray();
        rootObj.put("appkey", this.appkey);
        rootObj.put(TedPermissionActivity.EXTRA_PACKAGE_NAME, context.getPackageName());
        rootObj.put("version", IgawUpdateLog.getCommonVersion());
        try {
            PackageInfo pi = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            rootObj.put("app_version_name", pi.versionName);
            rootObj.put("app_version_code", pi.versionCode);
        } catch (Exception e) {
        }
        try {
            r1 = "third_party_id";
            rootObj.put("third_party_id", this.thirdPartyID);
        } catch (Exception e2) {
        }
        this.conversion_key = ReferralInfoDAO.getReferralInfo_conversionKey(context);
        referralInfoObj.put("conversion_key", this.conversion_key);
        this.session_no = ReferralInfoDAO.getReferralInfo_session_no(context);
        referralInfoObj.put("session_no", this.session_no);
        try {
            r1 = "referrer_param";
            referralInfoObj.put("referrer_param", URLEncoder.encode(ReferralInfoDAO.getReferralInfo_referrer_params(context), "UTF-8"));
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        rootObj.put("referral_info", referralInfoObj);
        ArrayList<Integer> cacheList = getConversionCache();
        if (cacheList != null && cacheList.size() > 0) {
            for (int i = 0; i < cacheList.size(); i++) {
                try {
                    conversionCacheArr.put(cacheList.get(i));
                } catch (Exception e4) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "error occurred during convert conversion_cache to integer", 0);
                }
            }
        }
        rootObj.put("conversion_cache", conversionCacheArr);
        this.adbrix_user_no = getADBrixUserNo();
        try {
            r0 = "adbrix_user_no";
            adbrixUserInfoObj.put("adbrix_user_no", this.adbrix_user_no);
        } catch (Exception e5) {
            adbrixUserInfoObj.put("adbrix_user_no", -1);
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "error occurred during convert adbrix_user_no to long", 0);
        }
        try {
            this.shard_no = getADBrixUserInfo_ShardNo();
            adbrixUserInfoObj.put(HttpManager.SHARD_NO, this.shard_no);
        } catch (Exception e6) {
            adbrixUserInfoObj.put(HttpManager.SHARD_NO, -1);
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "error occurred during convert shard_no to int", 0);
        }
        try {
            if (this.install_datetime == null || this.install_datetime.length() < 1) {
                this.install_datetime = getADBrixUserInfo_install_datetime();
            }
            if (this.install_datetime != null) {
                adbrixUserInfoObj.put(HttpManager.INSTALL_DATETIME, this.install_datetime);
                try {
                    r0 = "install_mdatetime";
                    adbrixUserInfoObj.put("install_mdatetime", df.parse(this.install_datetime).getTime());
                } catch (Exception e7) {
                }
            } else {
                adbrixUserInfoObj.put(HttpManager.INSTALL_DATETIME, "");
                adbrixUserInfoObj.put("install_mdatetime", "");
            }
        } catch (Exception e8) {
            adbrixUserInfoObj.put(HttpManager.INSTALL_DATETIME, "");
        }
        adbrixUserInfoObj.put("life_hour", calculateLifeHour());
        adbrixUserInfoObj.put("app_launch_count", this.app_launch_count);
        this.referral_key = getReferralKey();
        adbrixUserInfoObj.put("referral_key", this.referral_key);
        adbrixUserInfoObj.put(HttpManager.POSTBACK_REFERRER_DATA, getADBrixUserInfo_referral_data());
        adbrixUserInfoObj.put(HttpManager.POSTBACK_ENGAGEMENT_DATETIME, getADBrixUserInfo_reengagement_datetime());
        adbrixUserInfoObj.put(HttpManager.POSTBACK_REENGAGEMENT_DATA, getADBrixUserInfo_reengagement_data());
        adbrixUserInfoObj.put(HttpManager.REENGAGEMENT_CONVERSION_KEY, getADBrixUserInfo_reengagement_conversion_key());
        adbrixUserInfoObj.put(HttpManager.LAST_REFERRAL_KEY, getADBrixUserInfo_last_referral_key());
        adbrixUserInfoObj.put(HttpManager.LAST_REFERRAL_DATA, getADBrixUserInfo_last_referral_data());
        adbrixUserInfoObj.put(HttpManager.LAST_REFERRAL_DATETIME, getADBrixUserInfo_last_referral_datetime());
        try {
            adbrixUserInfoObj.put("set_referral_key", true);
            adbrixUserInfoObj.put("sig_type", 0);
        } catch (Exception e9) {
            e9.printStackTrace();
        }
        rootObj.put("adbrix_user_info", adbrixUserInfoObj);
        this.puid = this.didManager.getAESPuid(context);
        userInfoObj.put(PUID, checkIsNullOrEmptyAndReturnRegString(this.puid));
        this.mudid = getMhowUdid(context);
        userInfoObj.put("mudid", checkIsNullOrEmptyAndReturnRegString(this.mudid));
        if (OpenUDID_manager.isInitialized()) {
            this.openudid = this.didManager.getOpenUDID();
            userInfoObj.put(OpenUDID_manager.PREF_KEY, checkIsNullOrEmptyAndReturnRegString(this.openudid));
        } else {
            userInfoObj.put(OpenUDID_manager.PREF_KEY, "");
        }
        if (this.openudid == null || this.openudid.length() <= 0) {
            userInfoObj.put("openudid_md5", "");
        } else {
            DeviceIDManger deviceIDManger = this.didManager;
            String str = this.openudid;
            this.didManager.getClass();
            userInfoObj.put("openudid_md5", deviceIDManger.getOPENUDID(str, 100));
        }
        if (this.openudid == null || this.openudid.length() <= 0) {
            userInfoObj.put("openudid_sha1", "");
        } else {
            DeviceIDManger deviceIDManger2 = this.didManager;
            String str2 = this.openudid;
            this.didManager.getClass();
            userInfoObj.put("openudid_sha1", deviceIDManger2.getOPENUDID(str2, 101));
        }
        DeviceIDManger deviceIDManger3 = this.didManager;
        this.didManager.getClass();
        userInfoObj.put("android_id_md5", checkIsNullOrEmptyAndReturnRegString(deviceIDManger3.getAndroidId(context, 100)));
        DeviceIDManger deviceIDManger4 = this.didManager;
        this.didManager.getClass();
        userInfoObj.put("android_id_sha1", checkIsNullOrEmptyAndReturnRegString(deviceIDManger4.getAndroidId(context, 101)));
        DeviceIDManger deviceIDManger5 = this.didManager;
        this.didManager.getClass();
        userInfoObj.put("device_id_md5", deviceIDManger5.getDeviceID(context, 100));
        DeviceIDManger deviceIDManger6 = this.didManager;
        this.didManager.getClass();
        userInfoObj.put("device_id_sha1", checkIsNullOrEmptyAndReturnRegString(deviceIDManger6.getDeviceID(context, 101)));
        this.google_ad_id = adid;
        this.google_ad_id_opt_out = adidOptOut;
        userInfoObj.put(GOOGLE_AD_ID, this.google_ad_id);
        userInfoObj.put(GOOGLE_AD_ID_OPT_OUT, this.google_ad_id_opt_out);
        String initial_ad_id = AppImpressionDAO.getInitAdidtToSP(context);
        if (initial_ad_id == null || initial_ad_id.equals("")) {
            initial_ad_id = this.google_ad_id;
            AppImpressionDAO.setInitAdidtToSP(context, initial_ad_id);
        }
        userInfoObj.put(INIT_AD_ID, initial_ad_id);
        try {
            if (this.ag == null || this.ag.length() < 1) {
                PackageManager packageManager = context.getPackageManager();
                if (CommonHelper.checkSelfPermission(context, "android.permission.GET_ACCOUNTS")) {
                    Account[] acc = AccountManager.get(context).getAccountsByType("com.google");
                    int accCount = acc.length;
                    String accountList = "";
                    for (int i2 = 0; i2 < accCount; i2++) {
                        if (i2 > 0) {
                            accountList = new StringBuilder(String.valueOf(accountList)).append("|").toString();
                        }
                        accountList = new StringBuilder(String.valueOf(accountList)).append(DeviceIDManger.getSha1Value(acc[i2].name)).toString();
                    }
                    this.ag = accountList;
                }
            }
            userInfoObj.put(AG, this.ag);
        } catch (Exception e10) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "error occurred during get google account : " + e10.getMessage(), 0);
        }
        userInfoObj.put("odin", checkIsNullOrEmptyAndReturnRegString(this.didManager.getODIN1(context)));
        TelephonyManager tm = (TelephonyManager) context.getSystemService("phone");
        if (tm != null) {
            this.carrier = tm.getNetworkOperatorName();
        }
        if (this.carrier == null || this.carrier.equalsIgnoreCase("")) {
            this.carrier = "unknown";
        }
        this.carrier = URLEncoder.encode(this.carrier);
        userInfoObj.put("carrier", this.carrier);
        Locale defaultLocale = Locale.getDefault();
        userInfoObj.put("country", defaultLocale.getCountry());
        userInfoObj.put("language", defaultLocale.getLanguage());
        userInfoObj.put(ANDROID_ID, IgawBase64.encodeString(DeviceIDManger.getAndroidId(context)));
        rootObj.put("user_info", userInfoObj);
        try {
            JSONObject cohortObj = new JSONObject();
            cohortObj.put(COHORT_1_NAME, CohortDAO.getCohort(context, COHORT_1_NAME));
            cohortObj.put(COHORT_2_NAME, CohortDAO.getCohort(context, COHORT_2_NAME));
            cohortObj.put(COHORT_3_NAME, CohortDAO.getCohort(context, COHORT_3_NAME));
            rootObj.put("cohort_info", cohortObj);
        } catch (Exception e11) {
        }
        String adpopcorn_marketParam = context.getSharedPreferences("adpopcorn_parameter", 0).getString("adpopcorn_sdk_market", "");
        if (!adpopcorn_marketParam.equals("") && !adpopcorn_marketParam.equals("__UNDEFINED__MARKET__")) {
            this.market = adpopcorn_marketParam;
        }
        deviceInfoObj.put("vendor", this.market);
        if (Build.MODEL == null || Build.MODEL.equalsIgnoreCase("")) {
            this.model = "";
        } else {
            this.model = Build.MODEL;
        }
        deviceInfoObj.put("model", this.model);
        try {
            deviceInfoObj.put("kn", System.getProperty("os.version"));
        } catch (Exception e12) {
        }
        if (getWifiDevice(context)) {
            deviceInfoObj.put("is_wifi_only", true);
        } else {
            deviceInfoObj.put("is_wifi_only", false);
        }
        deviceInfoObj.put("network", getCustomNetworkInfo(context));
        deviceInfoObj.put("noncustomnetwork", getNonCustomNetworkInfo(context));
        if (VERSION.RELEASE != null && !VERSION.RELEASE.equalsIgnoreCase("")) {
            this.os = VERSION.RELEASE;
        }
        deviceInfoObj.put("os", "a_" + this.os);
        deviceInfoObj.put("ptype", "android");
        Display defaultDisplay = GetDisplay(context);
        if (context.getResources().getConfiguration().orientation == 2) {
            deviceInfoObj.put("width", defaultDisplay.getHeight());
            deviceInfoObj.put("height", defaultDisplay.getWidth());
            deviceInfoObj.put("is_portrait", false);
        } else {
            deviceInfoObj.put("width", defaultDisplay.getWidth());
            deviceInfoObj.put("height", defaultDisplay.getHeight());
            deviceInfoObj.put("is_portrait", true);
        }
        try {
            double round_utc_offset = round(((float) Calendar.getInstance().getTimeZone().getRawOffset()) / 3600000.0f);
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "UTC_OFFSET: " + round_utc_offset, 3, true);
            deviceInfoObj.put("utc_offset", round_utc_offset);
        } catch (Exception e13) {
            e13.printStackTrace();
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "UTC_OFFSET Error: " + e13.getMessage(), 0, false);
        }
        rootObj.put("device_info", deviceInfoObj);
        List<Pair<String, String>> demoInfo = getPersistantDemoInfo_v2();
        if (demoInfo != null) {
            for (Pair<String, String> item : demoInfo) {
                JSONObject aDemo = new JSONObject();
                aDemo.put("demo_key", item.first);
                aDemo.put("demo_value", item.second);
                demoArray.put(aDemo);
            }
        }
        rootObj.put("demographics", demoArray);
        if (complete_conversion_list != null && complete_conversion_list.size() > 0) {
            Iterator<Integer> it = complete_conversion_list.iterator();
            while (it.hasNext()) {
                completeConversionArr.put(it.next().intValue());
            }
        }
        rootObj.put("complete_conversions", completeConversionArr);
        if (activity_info_list != null) {
            Iterator<String> it2 = activity_info_list.iterator();
            while (it2.hasNext()) {
                String item2 = it2.next();
                try {
                    JSONObject jSONObject = new JSONObject(item2);
                    activityInfoArr.put(jSONObject);
                } catch (Exception e14) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "error occurred during fill activity info : " + e14.toString() + "\n contents : " + item2, 0);
                }
            }
        }
        rootObj.put("activity_info", activityInfoArr);
        if (imp_info_list != null) {
            Iterator<String> it3 = imp_info_list.iterator();
            while (it3.hasNext()) {
                try {
                    JSONObject jSONObject2 = new JSONObject(it3.next());
                    impInfoArr.put(jSONObject2);
                } catch (Exception e15) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "error occurred during fill imp info : " + e15.toString(), 0);
                }
            }
        }
        rootObj.put("impression_info", impInfoArr);
        if (deeplink_conversions != null) {
            try {
                JSONArray commerceConversionArray = new JSONArray();
                for (DeeplinkConversionItem item3 : deeplink_conversions) {
                    JSONObject commerceConversionObj = new JSONObject();
                    commerceConversionObj.put("click_id", item3.getCommerceClickID());
                    commerceConversionObj.put("conversion_key", item3.getConversionKey());
                    commerceConversionObj.put("link_params", item3.getLinkParams());
                    commerceConversionArray.put(commerceConversionObj);
                }
                rootObj.put("commerce_conversion", commerceConversionArray);
            } catch (Exception e16) {
            }
        }
        return rootObj;
    }

    private boolean getWifiDevice(Context context) {
        try {
            if (((TelephonyManager) context.getSystemService("phone")) == null) {
                this.isWifiDevice = true;
            } else {
                this.isWifiDevice = false;
            }
        } catch (Exception e) {
            this.isWifiDevice = false;
            e.printStackTrace();
        }
        return this.isWifiDevice;
    }

    private Display GetDisplay(Context context) {
        return ((WindowManager) context.getSystemService("window")).getDefaultDisplay();
    }

    public boolean isSecurity_enable() {
        return this.security_enable;
    }

    public void setSecurity_enable(boolean security_enable2) {
        this.security_enable = security_enable2;
    }

    public String getOpenudid() {
        return this.openudid;
    }

    public void setOpenudid(String openudid2) {
        this.openudid = openudid2;
    }

    public String getMhowUdid(Context context) {
        String deviceid = CoreIDDAO.getInstance().getIMEI(context);
        if (deviceid == null) {
            return deviceid;
        }
        try {
            if (!deviceid.equals("")) {
                return Mhows_AES_Util.encrypt(deviceid);
            }
            return "";
        } catch (Exception e) {
            e.printStackTrace();
            return deviceid;
        }
    }

    public String getDemographic(Context context, String key) {
        String result = null;
        if (context == null) {
            return result;
        }
        try {
            return context.getSharedPreferences("persistantDemoForTracking", 0).getString(key, null);
        } catch (Exception e) {
            e.printStackTrace();
            return result;
        }
    }

    public String getCustomNetworkInfo(Context context) {
        if (context == null) {
            return "unKnown";
        }
        try {
            if (CommonFrameworkImpl.REMOVE_NETWORKS_STATE_PERMISSION) {
                return "unKnown";
            }
            ConnectivityManager conMan = (ConnectivityManager) context.getSystemService("connectivity");
            if (conMan == null) {
                return "unKnown";
            }
            NetworkInfo mobile = conMan.getNetworkInfo(0);
            NetworkInfo wifi = conMan.getNetworkInfo(1);
            if (mobile != null && (mobile.getState() == State.CONNECTED || mobile.getState() == State.CONNECTING)) {
                return "mobile";
            }
            if (wifi != null) {
                if (wifi.getState() == State.CONNECTED || wifi.getState() == State.CONNECTING) {
                    return "wifi";
                }
            }
            return "unknown";
        } catch (Exception e) {
            e.printStackTrace();
            return "unKnown";
        }
    }

    public int getNonCustomNetworkInfo(Context context) {
        try {
            return ((TelephonyManager) context.getSystemService("phone")).getNetworkType();
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    public List<Pair<String, String>> getDemoInfo() {
        List<Pair<String, String>> result = new ArrayList<>();
        Map<String, ?> all = CommonFrameworkImpl.getContext().getSharedPreferences("demoForTracking", 0).getAll();
        if (all.size() == 0) {
            return null;
        }
        JSONObject localDemoGraphic = LocalDemograhpicDAO.getInstance(CommonFrameworkImpl.getContext()).convertDemographicInfoFromSP2JSONObject(CommonFrameworkImpl.getContext());
        for (String key : all.keySet()) {
            if (localDemoGraphic.has(key)) {
                try {
                    String local_value = localDemoGraphic.getString(key);
                    if (local_value == null) {
                        result.add(new Pair(key, (String) all.get(key)));
                        IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "Demographic info for tracking >> key: " + key + "; value :" + ((String) all.get(key)), 3, true);
                    } else {
                        String newValue = (String) all.get(key);
                        if (newValue != null && !newValue.equals(local_value)) {
                            result.add(new Pair(key, (String) all.get(key)));
                            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "Demographic info for tracking >> key: " + key + "; value :" + ((String) all.get(key)), 3, true);
                        }
                    }
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            } else {
                result.add(new Pair(key, (String) all.get(key)));
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "Demographic info for tracking >> key: " + key + "; value :" + ((String) all.get(key)), 3, true);
            }
        }
        return result;
    }

    public List<Pair<String, String>> getPersistantDemoInfo_v2() {
        List<Pair<String, String>> result = new ArrayList<>();
        Map<String, ?> all = CommonFrameworkImpl.getContext().getSharedPreferences("persistantDemoForTracking", 0).getAll();
        if (all.size() == 0) {
            return null;
        }
        for (String key : all.keySet()) {
            result.add(new Pair(key, (String) all.get(key)));
        }
        return result;
    }

    @Deprecated
    public List<NameValuePair> getPersistantDemoInfo() {
        if (VERSION.SDK_INT >= 23) {
            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "Pls update lastest IGAWORKS SDK", 2, false);
            try {
                Class.forName("org.apache.http");
            } catch (ClassNotFoundException e) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "Not found org.apache.http", 2, false);
                return null;
            }
        }
        List<NameValuePair> result = new ArrayList<>();
        Map<String, ?> all = CommonFrameworkImpl.getContext().getSharedPreferences("persistantDemoForTracking", 0).getAll();
        if (all.size() == 0) {
            return null;
        }
        for (String key : all.keySet()) {
            result.add(new BasicNameValuePair(key, (String) all.get(key)));
        }
        return result;
    }

    public static String convertActivityStringToJson(String prevGroup, String prevActivity, String group, String activity2, String param, String createdAt, String event_id) throws JSONException {
        JSONObject result = new JSONObject();
        result.put("prev_group", prevGroup);
        result.put("prev_activity", prevActivity);
        result.put("group", group);
        result.put("activity", activity2);
        if (param == null) {
            param = "";
        }
        result.put("param", param);
        result.put("event_id", event_id);
        result.put("created_at", createdAt);
        return result.toString();
    }

    public static String convertImpressionStringToJson(int campaignKey, String spaceKey, int resourceKey, String createdAt) throws JSONException {
        JSONObject result = new JSONObject();
        result.put("campaign_key", campaignKey);
        result.put("space_key", spaceKey);
        result.put("resource_key", resourceKey);
        result.put("created_at", createdAt);
        return result.toString();
    }

    @Deprecated
    public int getReferralInfo_conversionKey() {
        return ReferralInfoDAO.getReferralInfo_conversionKey(CommonFrameworkImpl.getContext());
    }

    public void setAllowDuplicationConversion(int conversionKey, int parentCK) {
        SharedPreferences AllowDuplicationConversionList = CommonFrameworkImpl.getContext().getSharedPreferences("AllowDuplicationConversionList", 0);
        String str = new StringBuilder(String.valueOf(parentCK)).append(";").append(conversionKey).toString();
        if (!AllowDuplicationConversionList.contains(str)) {
            Editor AllowDuplicationConversionListEdt = AllowDuplicationConversionList.edit();
            if (!AllowDuplicationConversionList.contains(new StringBuilder(String.valueOf(parentCK)).toString())) {
                AllowDuplicationConversionListEdt.putString(new StringBuilder(String.valueOf(parentCK)).toString(), new StringBuilder(String.valueOf(parentCK)).toString());
            }
            String parentKeyGroup = new StringBuilder(AbstractCPEImpressionDAO.PARENT_KEY_GROUP).append(parentCK).toString();
            if (!AllowDuplicationConversionList.contains(parentKeyGroup)) {
                AllowDuplicationConversionListEdt.putString(parentKeyGroup, parentKeyGroup);
            }
            AllowDuplicationConversionListEdt.putString(str, str);
            AllowDuplicationConversionListEdt.commit();
        }
    }

    public ArrayList<String> getAllowDuplicationConversions() {
        ArrayList<String> AllowDuplicationConversions = new ArrayList<>();
        try {
            Collection<?> values = CommonFrameworkImpl.getContext().getSharedPreferences("AllowDuplicationConversionList", 0).getAll().values();
            if (!(values == null || values.size() == 0)) {
                Iterator<?> it = values.iterator();
                while (it.hasNext()) {
                    try {
                        AllowDuplicationConversions.add((String) it.next());
                    } catch (Exception e) {
                    }
                }
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        return AllowDuplicationConversions;
    }

    public void setConversionCacheHistory(int conversionKey, long completeTime) {
        Editor inputConversionKey = CommonFrameworkImpl.getContext().getSharedPreferences("conversionCacheHistory", 0).edit();
        inputConversionKey.putLong(new StringBuilder(AbstractCPEImpressionDAO.PARENT_KEY_GROUP).append(conversionKey).toString(), completeTime);
        inputConversionKey.commit();
    }

    public ArrayList<DuplicationConversionKeyModel> getConversionCacheHistory() {
        ArrayList<DuplicationConversionKeyModel> list = new ArrayList<>();
        try {
            for (Entry<String, ?> entry : CommonFrameworkImpl.getContext().getSharedPreferences("conversionCacheHistory", 0).getAll().entrySet()) {
                list.add(new DuplicationConversionKeyModel(Long.valueOf(entry.getValue().toString()).longValue(), entry.getKey()));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return list;
    }

    public void setConversionCache(int conversionKey) {
        if (!tempConversionCache.contains(Integer.valueOf(conversionKey))) {
            tempConversionCache.add(Integer.valueOf(conversionKey));
        }
        SharedPreferences conversionPref = CommonFrameworkImpl.getContext().getSharedPreferences("conversionCache", 0);
        if (conversionPref.contains(new StringBuilder(String.valueOf(conversionKey)).toString())) {
            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "conversionKey was already saved in storage", 3);
            return;
        }
        Editor inputConversionKey = conversionPref.edit();
        inputConversionKey.putInt(new StringBuilder(String.valueOf(conversionKey)).toString(), conversionKey);
        inputConversionKey.commit();
    }

    public ArrayList<Integer> getConversionCache() {
        int aConversion;
        ArrayList<Integer> conversionCacheList = new ArrayList<>();
        try {
            Collection<?> values = CommonFrameworkImpl.getContext().getSharedPreferences("conversionCache", 0).getAll().values();
            if (!(values == null || values.size() == 0)) {
                for (Object next : values) {
                    try {
                        aConversion = ((Integer) next).intValue();
                    } catch (Exception e) {
                        try {
                            aConversion = Integer.parseInt((String) next);
                        } catch (Exception e2) {
                        }
                    }
                    conversionCacheList.add(Integer.valueOf(aConversion));
                }
            }
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        for (int indx = 0; indx < conversionCacheList.size(); indx++) {
            if (!tempConversionCache.contains(conversionCacheList.get(indx))) {
                tempConversionCache.add(conversionCacheList.get(indx));
            }
        }
        int referrerKey = ReferralInfoDAO.getReferralInfo_conversionKey(CommonFrameworkImpl.getContext());
        if (referrerKey != -1 && isNewInstall() && !tempConversionCache.contains(Integer.valueOf(referrerKey))) {
            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "add refererKey temporarily to cvCache: " + referrerKey, 2, false);
            tempConversionCache.add(Integer.valueOf(referrerKey));
        }
        return tempConversionCache;
    }

    public void setRetainedConversionCache(int conversionKey) {
        if (!tempRetainedConversionCache.contains(Integer.valueOf(conversionKey))) {
            tempRetainedConversionCache.add(Integer.valueOf(conversionKey));
        }
        SharedPreferences retainedconversionPref = CommonFrameworkImpl.getContext().getSharedPreferences("retainedconversionCache", 0);
        if (retainedconversionPref.contains(new StringBuilder(String.valueOf(conversionKey)).toString())) {
            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "retainedconversionCache was already saved in storage", 3);
            return;
        }
        Editor inputConversionKey = retainedconversionPref.edit();
        inputConversionKey.putInt(new StringBuilder(String.valueOf(conversionKey)).toString(), conversionKey);
        inputConversionKey.commit();
    }

    public void removeRetainedConversionCache(int conversionKey) {
        try {
            if (tempRetainedConversionCache.contains(Integer.valueOf(conversionKey))) {
                tempRetainedConversionCache.remove(Integer.valueOf(conversionKey));
            }
            SharedPreferences retainedconversionPref = CommonFrameworkImpl.getContext().getSharedPreferences("retainedconversionCache", 0);
            if (retainedconversionPref.contains(new StringBuilder(String.valueOf(conversionKey)).toString())) {
                Editor inputConversionKey = retainedconversionPref.edit();
                inputConversionKey.remove(new StringBuilder(String.valueOf(conversionKey)).toString());
                inputConversionKey.commit();
                return;
            }
            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "retainedconversionCache does't have conversion key: " + conversionKey, 3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public ArrayList<Integer> getRetainedConversionCache() {
        int aConversion;
        ArrayList<Integer> retainconversionCacheList = new ArrayList<>();
        try {
            Collection<?> values = CommonFrameworkImpl.getContext().getSharedPreferences("retainedconversionCache", 0).getAll().values();
            if (!(values == null || values.size() == 0)) {
                for (Object next : values) {
                    try {
                        aConversion = ((Integer) next).intValue();
                    } catch (Exception e) {
                        try {
                            aConversion = Integer.parseInt((String) next);
                        } catch (Exception e2) {
                        }
                    }
                    retainconversionCacheList.add(Integer.valueOf(aConversion));
                }
            }
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        for (int indx = 0; indx < retainconversionCacheList.size(); indx++) {
            if (!tempRetainedConversionCache.contains(retainconversionCacheList.get(indx))) {
                tempRetainedConversionCache.add(retainconversionCacheList.get(indx));
            }
        }
        int referrerKey = ReferralInfoDAO.getReferralInfo_conversionKey(CommonFrameworkImpl.getContext());
        if (referrerKey != -1 && isNewInstall() && !tempRetainedConversionCache.contains(Integer.valueOf(referrerKey))) {
            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "add refererKey temporarily to cvRetainedCache: " + referrerKey, 2, false);
            tempRetainedConversionCache.add(Integer.valueOf(referrerKey));
        }
        return tempRetainedConversionCache;
    }

    public void setProcessedConversions(int conversionKey) {
        if (!tempProcessedConversions.contains(Integer.valueOf(conversionKey))) {
            tempProcessedConversions.add(Integer.valueOf(conversionKey));
        }
        SharedPreferences processedConversionPref = CommonFrameworkImpl.getContext().getSharedPreferences("processedConversionCache", 0);
        if (processedConversionPref.contains(new StringBuilder(String.valueOf(conversionKey)).toString())) {
            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, new StringBuilder(String.valueOf(conversionKey)).append(" conversion was already saved in processedConversionCache").toString(), 3);
            return;
        }
        Editor edt = processedConversionPref.edit();
        edt.putInt(new StringBuilder(String.valueOf(conversionKey)).toString(), conversionKey);
        edt.commit();
    }

    public ArrayList<Integer> getProcessedConversions() {
        int aConversion;
        ArrayList<Integer> processedList = new ArrayList<>();
        try {
            Collection<?> values = CommonFrameworkImpl.getContext().getSharedPreferences("processedConversionCache", 0).getAll().values();
            if (!(values == null || values.size() == 0)) {
                for (Object next : values) {
                    try {
                        aConversion = ((Integer) next).intValue();
                    } catch (Exception e) {
                        try {
                            aConversion = Integer.parseInt((String) next);
                        } catch (Exception e2) {
                        }
                    }
                    processedList.add(Integer.valueOf(aConversion));
                }
            }
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        for (int indx = 0; indx < processedList.size(); indx++) {
            if (!tempProcessedConversions.contains(processedList.get(indx))) {
                tempProcessedConversions.add(processedList.get(indx));
            }
        }
        return tempProcessedConversions;
    }

    public boolean isNewInstall() {
        return this.isNewInstall;
    }

    public void setNewInstall(boolean isNewInstall2) {
        this.isNewInstall = isNewInstall2;
    }

    public void setCompleteConversions(ArrayList<Integer> completeConversionKeys) {
        SharedPreferences conversionPref = CommonFrameworkImpl.getContext().getSharedPreferences("completeConversions", 0);
        Iterator<Integer> it = completeConversionKeys.iterator();
        while (it.hasNext()) {
            int conversionKey = it.next().intValue();
            if (conversionPref.contains(conversionKey)) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "completeConversionKey was already saved in storage", 3);
            } else {
                Editor inputConversionKey = conversionPref.edit();
                inputConversionKey.putInt(conversionKey, conversionKey);
                inputConversionKey.commit();
            }
        }
    }

    public ArrayList<Integer> getCompleteConversions() {
        int aConversion;
        ArrayList<Integer> completeConversionsList = new ArrayList<>();
        try {
            Collection<?> values = CommonFrameworkImpl.getContext().getSharedPreferences("completeConversions", 0).getAll().values();
            if (values == null || values.size() == 0) {
                return null;
            }
            for (Object next : values) {
                try {
                    aConversion = ((Integer) next).intValue();
                } catch (Exception e) {
                    try {
                        aConversion = Integer.parseInt((String) next);
                    } catch (Exception e2) {
                    }
                }
                completeConversionsList.add(Integer.valueOf(aConversion));
            }
            return completeConversionsList;
        } catch (Exception e3) {
            e3.printStackTrace();
            return completeConversionsList;
        }
    }

    public void setADBrixUserInfo(long adbrix_user_no_, long life_hour_start_time) {
        if (this.adbrix_user_no <= 0 || adbrix_user_no_ != 0) {
            this.adbrix_user_no = adbrix_user_no_;
            Editor user_info_editor = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).edit();
            if (adbrix_user_no_ > -1) {
                user_info_editor.putLong("adbrix_user_no", adbrix_user_no_);
                user_info_editor.putLong("life_hour_start_time", life_hour_start_time);
            }
            user_info_editor.commit();
        }
    }

    public void setADBrixUserInfo_ReferralKey(long referral_key_) {
        if (this.referral_key <= 0 || referral_key_ != 0) {
            this.referral_key = referral_key_;
            Editor user_info_editor = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).edit();
            if (referral_key_ != -1) {
                user_info_editor.putLong("referral_key", referral_key_);
            }
            user_info_editor.commit();
        }
    }

    public void setADBrixUserInfo_SubReferralKey(String subreferral_key_) {
        Editor user_info_editor = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).edit();
        if (subreferral_key_ != null && subreferral_key_.length() > 0) {
            user_info_editor.putString("subreferral_key", subreferral_key_);
            this.subreferral_key = subreferral_key_;
        }
        user_info_editor.commit();
    }

    public void setADBrixUserInfo_referral_data(String referral_data_) {
        Editor user_info_editor = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).edit();
        if (referral_data_ != null && referral_data_.length() > 0 && !referral_data_.equals("null")) {
            user_info_editor.putString(HttpManager.POSTBACK_REFERRER_DATA, referral_data_);
            this.referral_data = referral_data_;
        }
        user_info_editor.commit();
    }

    public String getADBrixUserInfo_referral_data() {
        if (this.referral_data != null && !this.referral_data.equals("null") && this.referral_data.length() > 0) {
            return this.referral_data;
        }
        SharedPreferences adbrix_user_info_pref = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0);
        if (!adbrix_user_info_pref.contains(HttpManager.POSTBACK_REFERRER_DATA)) {
            return null;
        }
        this.referral_data = adbrix_user_info_pref.getString(HttpManager.POSTBACK_REFERRER_DATA, null);
        return this.referral_data;
    }

    public void setADBrixUserInfo_reengagement_data(String reengagement_data_) {
        Editor user_info_editor = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).edit();
        if (reengagement_data_ != null && reengagement_data_.length() > 0 && !reengagement_data_.equals("null")) {
            user_info_editor.putString(HttpManager.POSTBACK_REENGAGEMENT_DATA, reengagement_data_);
            this.reengagement_data = reengagement_data_;
        }
        user_info_editor.commit();
    }

    public String getADBrixUserInfo_reengagement_data() {
        if (this.reengagement_data != null && !this.reengagement_data.equals("null") && this.reengagement_data.length() > 0) {
            return this.reengagement_data;
        }
        SharedPreferences adbrix_user_info_pref = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0);
        if (!adbrix_user_info_pref.contains(HttpManager.POSTBACK_REENGAGEMENT_DATA)) {
            return null;
        }
        this.reengagement_data = adbrix_user_info_pref.getString(HttpManager.POSTBACK_REENGAGEMENT_DATA, null);
        return this.reengagement_data;
    }

    public String getADBrixUserInfo_Refusn() {
        SharedPreferences adbrix_user_info_pref = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0);
        if (adbrix_user_info_pref.contains(HttpManager.REF_USN)) {
            return adbrix_user_info_pref.getString(HttpManager.REF_USN, null);
        }
        return null;
    }

    public void setADBrixUserInfo_Refusn(String refusn_) {
        Editor user_info_editor = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).edit();
        if (refusn_ != null && refusn_.length() > 0) {
            user_info_editor.putString(HttpManager.REF_USN, refusn_);
            this.refusn = refusn_;
        }
        user_info_editor.commit();
    }

    public int getADBrixUserInfo_ShardNo() {
        if (this.shard_no > -1) {
            return this.shard_no;
        }
        SharedPreferences adbrix_user_info_pref = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0);
        if (adbrix_user_info_pref.contains(HttpManager.SHARD_NO)) {
            return adbrix_user_info_pref.getInt(HttpManager.SHARD_NO, -1);
        }
        return -1;
    }

    public void setADBrixUserInfo_ShardNo(int shardNo_) {
        try {
            Editor user_info_editor = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).edit();
            if (shardNo_ > -1) {
                user_info_editor.putInt(HttpManager.SHARD_NO, shardNo_);
                this.shard_no = shardNo_;
            }
            user_info_editor.commit();
        } catch (Exception e) {
        }
    }

    public String getADBrixUserInfo_install_datetime() {
        if (this.install_datetime != null && this.install_datetime.length() > 0) {
            return this.install_datetime;
        }
        SharedPreferences adbrix_user_info_pref = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0);
        if (adbrix_user_info_pref.contains(HttpManager.INSTALL_DATETIME)) {
            return adbrix_user_info_pref.getString(HttpManager.INSTALL_DATETIME, null);
        }
        return null;
    }

    public void setADBrixUserInfo_install_datetime(String installDatetime) {
        if (installDatetime != null) {
            try {
                if (installDatetime.length() != 0 && !installDatetime.equals("")) {
                    Editor user_info_editor = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).edit();
                    if (installDatetime != null && installDatetime.length() > 0) {
                        user_info_editor.putString(HttpManager.INSTALL_DATETIME, installDatetime);
                        this.install_datetime = installDatetime;
                    }
                    user_info_editor.commit();
                }
            } catch (Exception e) {
            }
        }
    }

    public String getADBrixUserInfo_reengagement_datetime() {
        if (this.reengagement_datetime != null && this.reengagement_datetime.length() > 0) {
            return this.reengagement_datetime;
        }
        SharedPreferences adbrix_user_info_pref = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0);
        if (adbrix_user_info_pref.contains(HttpManager.POSTBACK_ENGAGEMENT_DATETIME)) {
            return adbrix_user_info_pref.getString(HttpManager.POSTBACK_ENGAGEMENT_DATETIME, null);
        }
        return null;
    }

    public void setADBrixUserInfo_reengagment_datetime(String reengagementDatetime) {
        try {
            Editor user_info_editor = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).edit();
            if (reengagementDatetime != null && reengagementDatetime.length() > 0) {
                user_info_editor.putString(HttpManager.POSTBACK_ENGAGEMENT_DATETIME, reengagementDatetime);
                this.reengagement_datetime = reengagementDatetime;
            }
            user_info_editor.commit();
        } catch (Exception e) {
        }
    }

    public long getADBrixUserInfo_reengagement_conversion_key() {
        if (this.reengagement_conversion_key >= 0) {
            return this.reengagement_conversion_key;
        }
        SharedPreferences adbrix_user_info_pref = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0);
        try {
            this.reengagement_conversion_key = adbrix_user_info_pref.getLong(HttpManager.REENGAGEMENT_CONVERSION_KEY, -1);
        } catch (Exception e) {
            try {
                this.reengagement_conversion_key = Long.parseLong(adbrix_user_info_pref.getString(HttpManager.REENGAGEMENT_CONVERSION_KEY, "-1"));
            } catch (Exception e2) {
                this.reengagement_conversion_key = -1;
            }
        }
        return this.reengagement_conversion_key;
    }

    public void setADBrixUserInfo_reengagement_conversion_key(long reengagement_conversion_key_) {
        this.reengagement_conversion_key = reengagement_conversion_key_;
        Editor user_info_editor = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).edit();
        user_info_editor.putLong(HttpManager.REENGAGEMENT_CONVERSION_KEY, reengagement_conversion_key_);
        user_info_editor.commit();
    }

    public long getADBrixUserInfo_last_referral_key() {
        if (this.last_referral_key >= 0) {
            return this.last_referral_key;
        }
        SharedPreferences adbrix_user_info_pref = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0);
        try {
            this.last_referral_key = adbrix_user_info_pref.getLong(HttpManager.LAST_REFERRAL_KEY, -1);
        } catch (Exception e) {
            try {
                this.last_referral_key = Long.parseLong(adbrix_user_info_pref.getString(HttpManager.LAST_REFERRAL_KEY, "-1"));
            } catch (Exception e2) {
                this.last_referral_key = -1;
            }
        }
        return this.last_referral_key;
    }

    public void setADBrixUserInfo_last_referral_key(long last_referral_key_) {
        this.last_referral_key = last_referral_key_;
        Editor user_info_editor = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).edit();
        user_info_editor.putLong(HttpManager.LAST_REFERRAL_KEY, last_referral_key_);
        user_info_editor.commit();
    }

    public String getADBrixUserInfo_last_referral_datetime() {
        if (this.last_referral_datetime != null && this.last_referral_datetime.length() > 0) {
            return this.last_referral_datetime;
        }
        this.last_referral_datetime = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).getString(HttpManager.LAST_REFERRAL_DATETIME, "");
        return this.last_referral_datetime;
    }

    public void setADBrixUserInfo_last_referral_datetime(String last_referral_datetime_) {
        this.last_referral_datetime = last_referral_datetime_;
        try {
            Editor user_info_editor = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).edit();
            user_info_editor.putString(HttpManager.LAST_REFERRAL_DATETIME, last_referral_datetime_);
            user_info_editor.commit();
        } catch (Exception e) {
        }
    }

    public String getADBrixUserInfo_last_referral_data() {
        if (this.last_referral_data != null && this.last_referral_data.length() > 0) {
            return this.last_referral_data;
        }
        this.last_referral_data = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).getString(HttpManager.LAST_REFERRAL_DATA, "");
        return this.last_referral_data;
    }

    public void setADBrixUserInfo_last_referral_data(String last_referral_data_) {
        this.last_referral_data = last_referral_data_;
        Editor user_info_editor = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).edit();
        user_info_editor.putString(HttpManager.LAST_REFERRAL_DATA, last_referral_data_);
        user_info_editor.commit();
    }

    public String getADBrixUserInfo_SubReferralKey() {
        SharedPreferences adbrix_user_info_pref = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0);
        if (adbrix_user_info_pref.contains("subreferral_key")) {
            return adbrix_user_info_pref.getString("subreferral_key", null);
        }
        return null;
    }

    public void setChannelType(int channelType) {
        Editor user_info_editor = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).edit();
        if (channelType != -1) {
            user_info_editor.putInt("channel_type", channelType);
            this.channel_type = channelType;
        }
        user_info_editor.commit();
    }

    public long getADBrixUserNo() {
        SharedPreferences adbrix_user_info_pref = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0);
        try {
            return adbrix_user_info_pref.getLong("adbrix_user_no", -1);
        } catch (Exception e) {
            try {
                return Long.parseLong(adbrix_user_info_pref.getString("adbrix_user_no", "-1"));
            } catch (Exception e2) {
                return -1;
            }
        }
    }

    public long calculateLifeHour() {
        long start_time = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0).getLong("life_hour_start_time", 0);
        if (start_time == 0) {
            return -1;
        }
        long cal_time = (System.currentTimeMillis() - start_time) / 3600000;
        IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "calculate lifehour : " + cal_time, 3);
        return cal_time;
    }

    public long getReferralKey() {
        if (this.referral_key > -1) {
            return this.referral_key;
        }
        SharedPreferences adbrix_user_info_pref = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0);
        try {
            this.referral_key = adbrix_user_info_pref.getLong("referral_key", -1);
        } catch (Exception e) {
            try {
                this.referral_key = Long.parseLong(adbrix_user_info_pref.getString("referral_key", "-1"));
            } catch (Exception e2) {
                this.referral_key = -1;
            }
        }
        return this.referral_key;
    }

    public int getChannelType() {
        SharedPreferences adbrix_user_info_pref = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0);
        try {
            this.channel_type = adbrix_user_info_pref.getInt("channel_type", -1);
        } catch (Exception e) {
            try {
                this.channel_type = Integer.parseInt(adbrix_user_info_pref.getString("channel_type", "-1"));
            } catch (Exception e2) {
                this.channel_type = -1;
            }
        }
        return this.channel_type;
    }

    public void increaseAppLaunchCount() {
        try {
            SharedPreferences adbrix_user_info_pref = CommonFrameworkImpl.getContext().getSharedPreferences("adbrix_user_info", 0);
            Editor user_info_editor = adbrix_user_info_pref.edit();
            this.app_launch_count = adbrix_user_info_pref.getLong("app_launch_count", 0);
            this.app_launch_count++;
            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "app_launch_count : " + this.app_launch_count, 3);
            user_info_editor.putLong("app_launch_count", this.app_launch_count);
            user_info_editor.commit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean validateEmailFormat(String email) {
        if (email == null) {
            return false;
        }
        return Pattern.matches("[\\w\\~\\-\\.]+@[\\w\\~\\-]+(\\.[\\w\\~\\-]+)+", email.trim());
    }

    public static double round(float d) {
        return 0.5d * ((double) Math.round(2.0f * d));
    }
}