package com.igaworks.impl;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.pm.ApplicationInfo;
import android.net.Uri;
import android.net.Uri.Builder;
import android.os.SystemClock;
import android.util.Log;
import android.util.Pair;
import com.facebook.internal.ServerProtocol;
import com.igaworks.commerce.db.DemographicDAO;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.IgawUpdateLog;
import com.igaworks.core.OpenUDID_manager;
import com.igaworks.core.RequestParameter;
import com.igaworks.dao.ActivityInfoDAO;
import com.igaworks.dao.AdbrixDB_v2;
import com.igaworks.dao.AppImpressionDAO;
import com.igaworks.dao.CPEPromotionImpressionDAO;
import com.igaworks.dao.CoreIDDAO;
import com.igaworks.dao.CrashDAO;
import com.igaworks.dao.DeeplinkConversionRetryDAO;
import com.igaworks.dao.ReferralInfoDAO;
import com.igaworks.dao.tracking.TrackingActivitySQLiteDB;
import com.igaworks.dao.tracking.TrackingActivitySQLiteOpenHelper;
import com.igaworks.interfaces.CommonActivityListener;
import com.igaworks.interfaces.CommonInterface;
import com.igaworks.interfaces.DeferredLinkListener;
import com.igaworks.interfaces.ExtendedCommonActivityListener;
import com.igaworks.interfaces.ICommonAPCallbackListener;
import com.igaworks.interfaces.ICommonLiveOpsCallbackListener;
import com.igaworks.interfaces.IgawRewardItemEventListener;
import com.igaworks.model.DeeplinkConversionItem;
import com.igaworks.model.DeeplinkReEngagementConversion;
import com.igaworks.net.CommonHttpManager;
import com.igaworks.net.HttpManager;
import com.igaworks.util.CommonHelper;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.Task;
import com.igaworks.util.bolts_task.TaskUtils;
import io.fabric.sdk.android.services.events.EventsFilesManager;
import io.fabric.sdk.android.services.settings.SettingsJsonConstants;
import java.io.UnsupportedEncodingException;
import java.lang.Thread.State;
import java.net.URL;
import java.net.URLDecoder;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import org.json.JSONException;
import org.json.JSONObject;

public abstract class CommonFrameworkImpl implements CommonInterface {
    protected static long ContinueSessionMillis = 60000;
    public static final List<String> GROUPS_FOR_TRACKING_INSTANTLY = new ArrayList();
    public static boolean REMOVE_NETWORKS_STATE_PERMISSION = false;
    /* access modifiers changed from: private */
    public static List<Integer> TempProcessedConversionList = new ArrayList();
    /* access modifiers changed from: protected */
    public static Context appContext;
    protected static String appkey = null;
    private static boolean callStartApplicationAlready = false;
    protected static IgawRewardItemEventListener clientRewardlistener;
    protected static Map<String, ExtendedCommonActivityListener> eListeners;
    /* access modifiers changed from: protected */
    public static long endSessionParam = 0;
    protected static long endTimer = 0;
    protected static String hashkey = null;
    public static CommonHttpManager httpManager = null;
    public static boolean isFocusOnForCrashlytics = false;
    private static boolean isInitializingAppInfo = false;
    public static boolean isPremiumPostBack = false;
    public static boolean isTest = false;
    protected static Map<String, CommonActivityListener> listeners;
    protected static List<Pair<String, String>> localDemographicInfo;
    private static final Object lock = new Object();
    protected static String marketInfo = null;
    public static boolean needPermission = false;
    public static RequestParameter parameter;
    protected static String prev_activity = "";
    protected static String prev_group = "";
    public static List<String> processedClickID = new ArrayList();
    protected static List<String> receiverComponents = new ArrayList();
    protected static List<JSONObject> restoreForNullContext = new ArrayList();
    protected static boolean security_enable = false;
    protected static int session_stack_count = 0;
    protected static boolean shouldSendCompleteCall = false;
    protected static long startSessionTime = 0;
    protected static boolean test_server_enable = false;
    protected static String thirdPartyID = null;
    String activity_info = "";
    private ICommonAPCallbackListener commonAPCallbackListener;
    private ICommonLiveOpsCallbackListener commonLiveOpsCallbackListener;
    private ReferrerThread mReferrerThread = null;
    private SimpleDateFormat sdf = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT, Locale.KOREA);

    static {
        GROUPS_FOR_TRACKING_INSTANTLY.add("fte");
        GROUPS_FOR_TRACKING_INSTANTLY.add("buy");
    }

    public static Context getContext() {
        return appContext;
    }

    public static void setContext(Context context) {
        if (context instanceof Activity) {
            appContext = context.getApplicationContext();
        } else {
            appContext = context;
        }
    }

    public static void addActivityListener(String key, CommonActivityListener listener) {
        if (listeners == null) {
            listeners = new HashMap();
        }
        if (!listeners.containsKey(key)) {
            listeners.put(key, listener);
        }
    }

    public static Collection<CommonActivityListener> getActivityListener() {
        if (listeners == null) {
            return null;
        }
        return listeners.values();
    }

    public static void addExtendedActivityListener(String key, ExtendedCommonActivityListener listener) {
        if (eListeners == null) {
            eListeners = new HashMap();
        }
        if (!eListeners.containsKey(key)) {
            eListeners.put(key, listener);
        }
    }

    public static Collection<ExtendedCommonActivityListener> getExtendedActivityListener() {
        if (eListeners == null) {
            return null;
        }
        return eListeners.values();
    }

    /* access modifiers changed from: protected */
    public CommonHttpManager getHttpManager(Context context) {
        initAppInfo(context);
        if (httpManager == null) {
            synchronized (lock) {
                if (httpManager == null) {
                    httpManager = new CommonHttpManager();
                }
            }
        }
        return httpManager;
    }

    /* JADX WARNING: No exception handlers in catch block: Catch:{  } */
    public void initAppInfo(Context context) {
        boolean haveAllRequiredPermisison = true;
        try {
            if ((appkey == null || hashkey == null) && !isInitializingAppInfo) {
                isInitializingAppInfo = true;
                if (needPermission) {
                    if (AppImpressionDAO.getRequestPermisisonAlready(context)) {
                        CommonHelper.CheckandRequestPermissionForCommonSDK(context);
                    } else {
                        CommonHelper.RequestPermissionForCommonSDK(context);
                        AppImpressionDAO.addRequestPermissionAlready(context);
                    }
                }
                ApplicationInfo ai = context.getPackageManager().getApplicationInfo(context.getPackageName(), 128);
                if (ai.metaData == null) {
                    throw new Exception("ADBrix SDK can not find meta-data tags required. Please check that meta-data tag is in the application tag.");
                }
                if (ai.metaData.containsKey("adbrix_app_key")) {
                    appkey = String.valueOf(ai.metaData.get("adbrix_app_key"));
                    if (ai.metaData.containsKey("adbrix_hash_key")) {
                        hashkey = String.valueOf(ai.metaData.get("adbrix_hash_key"));
                        if (ai.metaData.containsKey("adbrix_market_info")) {
                            marketInfo = String.valueOf(ai.metaData.get("adbrix_market_info"));
                        } else {
                            marketInfo = "google";
                        }
                    } else {
                        throw new Exception("ADBrix SDK can not find meta-data tag named 'adbrix_hash_key'. please check a menifest file and add 'adbrix_hash_key'. ");
                    }
                } else if (ai.metaData.containsKey("adPOPcorn_media_key")) {
                    appkey = (String) ai.metaData.get("adPOPcorn_media_key");
                    if (ai.metaData.containsKey("adPOPcorn_hash_key")) {
                        hashkey = (String) ai.metaData.get("adPOPcorn_hash_key");
                        if (ai.metaData.containsKey("adPOPcorn_market_info")) {
                            marketInfo = (String) ai.metaData.get("adPOPcorn_market_info");
                        } else {
                            marketInfo = "google";
                        }
                    } else {
                        throw new Exception("ADBrix SDK can not find meta-data tag named 'adPOPcorn_hash_key'. please check a menifest file and add 'adPOPcorn_hash_key'. ");
                    }
                } else if (ai.metaData.containsKey("igaworks_app_key")) {
                    appkey = String.valueOf(ai.metaData.get("igaworks_app_key"));
                    if (ai.metaData.containsKey("igaworks_hash_key")) {
                        hashkey = String.valueOf(ai.metaData.get("igaworks_hash_key"));
                        if (ai.metaData.containsKey("igaworks_market_info")) {
                            marketInfo = String.valueOf(ai.metaData.get("igaworks_market_info"));
                        } else {
                            marketInfo = "google";
                        }
                    } else {
                        throw new Exception("ADBrix SDK can not find meta-data tag named 'igaworks_hash_key'. please check a menifest file and add 'igaworks_hash_key'. ");
                    }
                } else {
                    throw new Exception("ADBrix SDK can not find meta-data tag named 'igaworks_app_key'. please check a menifest file and add 'igaworks_app_key'. ");
                }
                try {
                    if (ai.metaData.containsKey("igaworks_third_party_id")) {
                        thirdPartyID = String.valueOf(ai.metaData.get("igaworks_third_party_id"));
                    }
                } catch (Exception e) {
                }
                OpenUDID_manager.sync(context);
                synchronized (lock) {
                    session_stack_count = 0;
                }
                try {
                    boolean canAccessInternet = CommonHelper.checkSelfPermission(context, "android.permission.INTERNET");
                    boolean canAccessNetworkState = CommonHelper.checkSelfPermission(context, "android.permission.ACCESS_NETWORK_STATE");
                    boolean canReadExternalStorage = CommonHelper.checkSelfPermission(context, "android.permission.READ_EXTERNAL_STORAGE");
                    boolean canWriteExternalStrorage = CommonHelper.checkSelfPermission(context, "android.permission.WRITE_EXTERNAL_STORAGE");
                    if (!canAccessInternet || !canAccessNetworkState || !canReadExternalStorage || !canWriteExternalStrorage) {
                        haveAllRequiredPermisison = false;
                    }
                    if (CommonFrameworkFactory.isHasAdbrixSDK) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > adbrix version : " + IgawUpdateLog.getVersion(), 3, false);
                    } else {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > common only", 3, false);
                    }
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > common version : " + IgawUpdateLog.getCommonVersion(), 3, false);
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > appkey : " + appkey, 3, false);
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > marketInfo : " + marketInfo, 3, false);
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > thirdPartyInfo : " + thirdPartyID, 3, false);
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > set READ_EXTERNAL_STORAGE permission : " + canReadExternalStorage, 3, false);
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > set WRITE_EXTERNAL_STORAGE permission : " + canWriteExternalStrorage, 3, false);
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > set Adbrix Receiver : " + CommonHelper.checkReceiver(context), 3, false);
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > have all required permisison: " + haveAllRequiredPermisison, 3, false);
                } catch (Exception e1) {
                    e1.printStackTrace();
                    Log.e(IgawConstant.QA_TAG, "Error: " + e1.getMessage().toString());
                }
                RequestParameter.getATRequestParameter(context).setAppKey(appkey);
                RequestParameter.getATRequestParameter(context).setHashkey(hashkey);
                isInitializingAppInfo = false;
            }
        } catch (Exception e2) {
            e2.printStackTrace();
            throw new RuntimeException(new Exception("ADBrix >> AndroidManifest.xml setting Error : Check AndroidManifest.xml file -> Are meta-data tags in application tag"));
        }
    }

    /* access modifiers changed from: protected */
    public void activity(String group, String activityName, String param, String createdAt, Context context) {
        try {
            activityImpl(group, activityName, param, createdAt);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /* access modifiers changed from: protected */
    public void activityImpl(String group, String activityName, String param, String createdAt) {
        String created_at;
        try {
            Date date = Calendar.getInstance().getTime();
            String event_id = UUID.randomUUID().toString();
            if (createdAt != null && createdAt.length() >= 1) {
                created_at = createdAt;
            } else if (getContext() == null) {
                created_at = "";
            } else if (RequestParameter.getATRequestParameter(getContext()).getADBrixUserNo() > 0) {
                created_at = CommonHelper.GetKSTServerTimeAsString(getContext());
            } else {
                created_at = "";
            }
            if (getContext() == null) {
                if (!group.equals("error")) {
                    JSONObject restoreObj = new JSONObject();
                    restoreObj.put("group", group);
                    restoreObj.put("activity", activityName);
                    restoreObj.put("param", param);
                    restoreObj.put("createdAt", created_at);
                    restoreForNullContext.add(restoreObj);
                }
                Log.e(IgawConstant.QA_TAG, "ADBrixManager > application context error, please check context value. startSession() should be called at least once.");
                return;
            }
            initAppInfo(getContext());
            IgawLogger.Logging(getContext(), IgawConstant.QA_TAG, "ADBrixManager > activity : " + prev_group + " / " + prev_activity + " / " + group + " / " + activityName + " / " + param + " / " + created_at, 3, false);
            try {
                this.activity_info = RequestParameter.convertActivityStringToJson(prev_group, prev_activity, group, activityName, param, created_at, event_id);
            } catch (Exception e) {
                if (param != null) {
                    try {
                        this.activity_info += "{\"prev_group\":" + "\"" + prev_group + "\"" + "," + "\"prev_activity\":" + "\"" + prev_activity + "\"," + "\"group\":" + "\"" + group + "\"" + "," + "\"activity\":" + "\"" + activityName + "\"" + "," + "\"param\":" + "\"" + param + "\"" + "," + "\"event_id\":" + "\"" + event_id + "\"" + "," + "\"created_at\":" + "\"" + created_at + "\"}";
                    } catch (Exception e1) {
                        e1.printStackTrace();
                        Log.e(IgawConstant.QA_TAG, "activityImpl Error: " + e1.getMessage());
                    }
                } else {
                    this.activity_info += "{\"prev_group\":" + "\"" + prev_group + "\"" + "," + "\"prev_activity\":" + "\"" + prev_activity + "\"," + "\"group\":" + "\"" + group + "\"" + "," + "\"activity\":" + "\"" + activityName + "\"" + "," + "\"param\":" + "\"\"" + "," + "\"event_id\":" + "\"" + event_id + "\"" + "," + "\"created_at\":" + "\"" + created_at + "\"}";
                }
                IgawLogger.Logging(getContext(), IgawConstant.QA_TAG, "error occurred during create activity_info text : " + e.toString(), 0);
            }
            TrackingActivitySQLiteDB.getInstance(getContext()).addTrackingActivityAsyn(date.getTime() + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR + group + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR + activityName, this.activity_info);
            try {
                parameter = RequestParameter.getATRequestParameter(getContext());
                if (parameter.getappLaunchCount() < 1 && parameter.getReferralKey() < 1) {
                    ActivityInfoDAO.addActivityInfoForReferral(getContext(), date.getTime() + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR + group + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR + activityName, this.activity_info);
                }
            } catch (Exception e2) {
                IgawLogger.Logging(getContext(), IgawConstant.QA_TAG, "error occurred during add referralActivityForTracking in activity() : " + e2.toString() + " / " + e2.getMessage(), 0, false);
            }
            if (!group.equals(SettingsJsonConstants.SESSION_KEY) || !activityName.equals("end")) {
                prev_activity = activityName;
                prev_group = group;
            }
            if (getActivityListener() != null) {
                for (CommonActivityListener item : getActivityListener()) {
                    item.onActivityCalled(getContext(), group, activityName, parameter);
                }
            }
            if (!GROUPS_FOR_TRACKING_INSTANTLY.contains(group)) {
                return;
            }
            if (group.equals(SettingsJsonConstants.SESSION_KEY) && (activityName.equals("start") || activityName.equals("end"))) {
                return;
            }
            if (CommonHelper.checkInternetConnection(getContext())) {
                flush();
            } else {
                IgawLogger.Logging(getContext(), IgawConstant.QA_TAG, "Can not connect to Adbrix. No internet connection now", 2, true);
            }
        } catch (Exception e3) {
            e3.printStackTrace();
        }
    }

    public void startApplicationForInternalUse(Context context) {
        if (!callStartApplicationAlready) {
            callStartApplicationAlready = true;
            try {
                setContext(context);
                IgawLogger.Logging(getContext(), IgawConstant.QA_TAG, "IgawSDK >> initialized", 3, false);
                CoreIDDAO.getInstance().initialize(getContext());
                parameter = RequestParameter.getATRequestParameter(getContext());
                httpManager = getHttpManager(getContext());
                initAppInfo(getContext());
                parameter = RequestParameter.getATRequestParameter(getContext());
                parameter.setAppKey(appkey);
                parameter.setMc(appkey);
                parameter.setThirdPartyID(thirdPartyID);
                parameter.setActivityName("start");
                parameter.setMarketPlace(marketInfo);
                parameter.setSecurity_enable(security_enable);
                parameter.setHashkey(hashkey);
                InternalAction.getInstance().sendOphanActivities(context, isTest, httpManager);
                if (!(Thread.getDefaultUncaughtExceptionHandler() instanceof CustomExceptionHandler)) {
                    Thread.setDefaultUncaughtExceptionHandler(new CustomExceptionHandler());
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public void startSession(Context activityContext) {
        try {
            Class.forName("com.igaworks.adbrix.impl.ADBrixFrameworkFactory");
        } catch (Exception e) {
            IgawLogger.Logging(activityContext, IgawConstant.QA_TAG, "IgawCommon >> Common only sdk mode.", 3, false);
        }
        try {
            setContext(activityContext);
            parameter = RequestParameter.getATRequestParameter(getContext());
            httpManager = getHttpManager(activityContext);
            initAppInfo(activityContext);
            try {
                if (!callStartApplicationAlready) {
                    callStartApplicationAlready = true;
                    InternalAction.getInstance().sendOphanActivities(activityContext, isTest, httpManager);
                    CoreIDDAO.getInstance().initialize(activityContext);
                    IgawLogger.Logging(getContext(), IgawConstant.QA_TAG, "IgawSDK >> initialized.", 3, false);
                }
            } catch (Exception e1) {
                Log.e(IgawConstant.QA_TAG, "sendOphanActivities Error: " + e1.getMessage());
            }
            Task.forResult(null).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Object, Void>() {
                public Void then(Task<Object> task) {
                    try {
                        SharedPreferences tracerSP = CommonFrameworkImpl.getContext().getSharedPreferences("activityForTracking", 0);
                        Editor trackingEditor = tracerSP.edit();
                        Collection<?> trackingCollection = null;
                        if (trackingCollection == null || trackingCollection.size() < 1) {
                            trackingCollection = tracerSP.getAll().keySet();
                        }
                        if (!(trackingCollection == null || trackingCollection.size() == 0)) {
                            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "Compat: Copy app tracking from SP to SQLite. Size:  " + trackingCollection.size(), 2, true);
                            Iterator<?> it = trackingCollection.iterator();
                            while (it.hasNext()) {
                                String key = (String) it.next();
                                String activity = tracerSP.getString(key, null);
                                trackingEditor.remove(key);
                                if (activity != null && !activity.equals("")) {
                                    TrackingActivitySQLiteDB.getInstance(CommonFrameworkImpl.getContext()).addTrackingActivityAsyn(key, activity);
                                }
                            }
                            trackingEditor.apply();
                        }
                        SharedPreferences promotionImpressionSP = CommonFrameworkImpl.getContext().getSharedPreferences(CPEPromotionImpressionDAO.CPE_PROMOTION_IMPRESSION_SP_NAME, 0);
                        Editor promotionImpressionEditor = promotionImpressionSP.edit();
                        Collection<?> impressCollection = null;
                        if (impressCollection == null || impressCollection.size() < 1) {
                            impressCollection = promotionImpressionSP.getAll().keySet();
                        }
                        if (!(impressCollection == null || impressCollection.size() == 0)) {
                            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "Compat: Copy impression from SP to SQLite. Size: " + impressCollection.size(), 2, true);
                            Iterator<?> it2 = impressCollection.iterator();
                            while (it2.hasNext()) {
                                String key2 = (String) it2.next();
                                String activity2 = promotionImpressionSP.getString(key2, null);
                                promotionImpressionEditor.remove(key2);
                                if (activity2 != null && !activity2.equals("")) {
                                    try {
                                        JSONObject impObj = new JSONObject(activity2);
                                        Boolean isFirstTime = null;
                                        String conversionKey = null;
                                        try {
                                            if (impObj.has(TrackingActivitySQLiteOpenHelper.IP_IS_FIRST_TIME)) {
                                                isFirstTime = Boolean.valueOf(impObj.getBoolean(TrackingActivitySQLiteOpenHelper.IP_IS_FIRST_TIME));
                                            }
                                            if (impObj.has("conversion_key")) {
                                                conversionKey = impObj.getString("conversion_key");
                                            }
                                            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "IP_CAMPAIGN_KEY:" + impObj.getInt("campaign_key") + " IP_RESOURCE_KEY:" + impObj.getInt("resource_key") + " IP_SPACE_KEY:" + impObj.getString("space_key") + " IP_CREATED_AT:" + impObj.getString("created_at") + " isFirstTime: " + isFirstTime + " conversionKey:" + conversionKey, 3, true);
                                            TrackingActivitySQLiteDB.getInstance(CommonFrameworkImpl.getContext()).setImpressionData(CommonFrameworkImpl.getContext(), impObj.getInt("campaign_key"), impObj.getInt("resource_key"), impObj.getString("space_key"), impObj.getString("created_at"), conversionKey, isFirstTime);
                                        } catch (JSONException e) {
                                            e = e;
                                            JSONObject jSONObject = impObj;
                                            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "onStartSession: Impression Compat error: " + e.toString(), 0);
                                        }
                                    } catch (JSONException e2) {
                                        e = e2;
                                        IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "onStartSession: Impression Compat error: " + e.toString(), 0);
                                    }
                                }
                            }
                            promotionImpressionEditor.apply();
                        }
                    } catch (Exception e3) {
                        Log.e(IgawConstant.QA_TAG, "copy error: " + e3.getMessage());
                        e3.printStackTrace();
                    } catch (OutOfMemoryError Err) {
                        Log.w(IgawConstant.QA_TAG, "Internal Update >> OOM Error: " + Err.getMessage());
                    }
                    return null;
                }
            }, (Executor) InternalAction.NETWORK_EXECUTOR);
            startSessionImpl(activityContext);
            restoreActivityForNullContext(getContext());
            List<String> crashInfos = CrashDAO.getCrashes(activityContext);
            IgawLogger.Logging(activityContext, IgawConstant.QA_TAG, "We have crash info count " + crashInfos.size(), 2, true);
            if (crashInfos != null && crashInfos.size() > 0) {
                try {
                    List<JSONObject> pArr = new ArrayList<>();
                    IgawLogger.Logging(activityContext, IgawConstant.QA_TAG, "Start to retrry sending crashReporting", 2, true);
                    if (crashInfos != null && crashInfos.size() > 0) {
                        try {
                            for (String pJsonString : crashInfos) {
                                pArr.add(new JSONObject(pJsonString));
                            }
                            IgawLogger.Logging(activityContext, IgawConstant.QA_TAG, "Start to retrry sending crashReporting II " + pArr.toString(), 2, true);
                            httpManager.reportingCrash(parameter, getContext(), pArr);
                        } catch (Exception e2) {
                            e2.printStackTrace();
                        }
                    }
                } catch (Exception e3) {
                    e3.printStackTrace();
                }
            }
        } catch (Exception e4) {
            e4.printStackTrace();
        }
    }

    private void startSessionImpl(Context activityContext) {
        try {
            isFocusOnForCrashlytics = true;
            dailyRetentionEvent(getContext());
            boolean session_continue = false;
            httpManager = getHttpManager(getContext());
            IgawLogger.Logging(getContext(), IgawConstant.QA_TAG, "ADBrixManager > startSession() : stack_count :" + session_stack_count, 3, false);
            parameter = RequestParameter.getATRequestParameter(getContext());
            parameter.setAppKey(appkey);
            parameter.setMc(appkey);
            parameter.setThirdPartyID(thirdPartyID);
            parameter.setActivityName("start");
            parameter.setMarketPlace(marketInfo);
            parameter.setSecurity_enable(security_enable);
            parameter.setHashkey(hashkey);
            synchronized (lock) {
                if (session_stack_count >= 4) {
                    IgawLogger.Logging(getContext(), IgawConstant.QA_TAG, "ADBrixManager > startSession() : The startSession API is called continuously without endSession API. Please make sure that the startSession and endSession API is called as a pair of an activity unit", 0, false);
                    session_stack_count = 0;
                    endTimer = 0;
                }
            }
            if (parameter.getReferralKey() != -1 && parameter.getADBrixUserNo() >= 1 && !ReferralInfoDAO.getOnReceiveReferralFlag(getContext()) && AppImpressionDAO.getSynAdbrix(getContext())) {
                try {
                    this.mReferrerThread = null;
                } catch (Exception exception) {
                    exception.printStackTrace();
                }
            } else if (this.mReferrerThread == null || this.mReferrerThread.getState() == State.TERMINATED) {
                this.mReferrerThread = new ReferrerThread();
                this.mReferrerThread.start();
            }
            if (session_stack_count != 0) {
                session_continue = true;
                shouldSendCompleteCall = false;
            } else if (endTimer <= 0) {
                shouldSendCompleteCall = true;
                startSessionTime = SystemClock.elapsedRealtime();
            } else if (SystemClock.elapsedRealtime() - endTimer <= ContinueSessionMillis) {
                session_continue = true;
                shouldSendCompleteCall = false;
            } else {
                shouldSendCompleteCall = true;
                startSessionTime = SystemClock.elapsedRealtime();
            }
            if (shouldSendCompleteCall) {
                parameter.increaseAppLaunchCount();
            }
            if (!session_continue) {
                new Thread() {
                    public void run() {
                        try {
                            String stringJson = CommonHelper.loadJSONFromS3(HttpManager.cfg_domain + RequestParameter.getATRequestParameter(CommonFrameworkImpl.getContext()).getAppkey() + HttpManager.CONFIG_REQUEST_URL_FOR_ADBrix);
                            if (stringJson != null) {
                                JSONObject jsonObj = new JSONObject(stringJson);
                                if (jsonObj != null && jsonObj.getJSONObject("commerce") != null) {
                                    CommonFrameworkImpl.isPremiumPostBack = jsonObj.getJSONObject("commerce").getBoolean("premium_postback");
                                    Log.d(IgawConstant.QA_TAG, "premium_postback of commerce is activated! premium_flag :" + CommonFrameworkImpl.isPremiumPostBack);
                                }
                            }
                        } catch (JSONException e) {
                            Log.e(IgawConstant.QA_TAG, "premium_postback of commerce error : " + e);
                        }
                    }
                }.start();
            }
            if (getActivityListener() != null) {
                for (CommonActivityListener item : getActivityListener()) {
                    item.onStartSession(activityContext, parameter, session_continue);
                }
            }
            if (!session_continue) {
                endSessionParam = 0;
            }
            if (!(parameter == null || parameter.getADBrixUserNo() == -1)) {
                InternalAction.getInstance().trackingForAdbrixCall(getContext(), isTest, httpManager, SettingsJsonConstants.SESSION_KEY, "start", endSessionParam);
            }
            endTimer = 0;
            synchronized (lock) {
                session_stack_count++;
            }
            if (!session_continue) {
                prev_activity = "";
                prev_group = "";
                activity(SettingsJsonConstants.SESSION_KEY, "start", null, null, getContext());
            }
            if (activityContext instanceof Activity) {
                deeplinkConversion((Activity) activityContext, false);
            } else {
                Log.d(IgawConstant.QA_TAG, "appContext is not Activity context");
            }
            if (CommonHelper.checkInternetConnection(getContext())) {
                resendDeeplinkConversion(getContext());
            }
            if (parameter != null) {
                IgawLogger.Logging(getContext(), IgawConstant.QA_TAG, String.format("channel_type : %d", new Object[]{Integer.valueOf(parameter.getChannelType())}), 3, false);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void endSession() {
        try {
            endSessionImpl();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void endSessionImpl() {
        try {
            isFocusOnForCrashlytics = false;
            if (getContext() == null) {
                Log.e(IgawConstant.QA_TAG, "ADBrixManager > application context error, please check context value. startSession() should be called at least once.");
                return;
            }
            try {
                appContext = appContext.getApplicationContext();
            } catch (Exception e) {
            }
            IgawLogger.Logging(getContext(), IgawConstant.QA_TAG, "endSession : statck_count : " + session_stack_count, 3, false);
            httpManager = getHttpManager(getContext());
            long endSession = SystemClock.elapsedRealtime();
            synchronized (lock) {
                if (session_stack_count > 0) {
                    session_stack_count--;
                }
                if (session_stack_count == 0) {
                    endTimer = endSession;
                    endSessionParam = endSession - startSessionTime;
                } else {
                    endTimer = 0;
                }
            }
            if (!(session_stack_count != 0 || parameter == null || parameter.getADBrixUserNo() == -1)) {
                InternalAction.getInstance().trackingForAdbrixCall(getContext(), isTest, httpManager, SettingsJsonConstants.SESSION_KEY, "end", 0);
            }
            Task.forResult(null).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Void, Void>() {
                /* JADX WARNING: Code restructure failed: missing block: B:20:0x004b, code lost:
                    r6 = move-exception;
                 */
                /* JADX WARNING: Code restructure failed: missing block: B:21:0x004c, code lost:
                    android.util.Log.e(com.igaworks.core.IgawConstant.QA_TAG, "Send demographic Error: " + r6.getMessage());
                    r6.printStackTrace();
                 */
                /* JADX WARNING: Code restructure failed: missing block: B:26:0x0085, code lost:
                    r0 = move-exception;
                 */
                /* JADX WARNING: Code restructure failed: missing block: B:27:0x0086, code lost:
                    android.util.Log.w(com.igaworks.core.IgawConstant.QA_TAG, "Send demographic >> OOM Error: " + r0.getMessage());
                 */
                /* JADX WARNING: Failed to process nested try/catch */
                /* JADX WARNING: Removed duplicated region for block: B:26:0x0085 A[ExcHandler: OutOfMemoryError (r0v0 'Err' java.lang.OutOfMemoryError A[CUSTOM_DECLARE]), Splitter:B:1:0x0001] */
                /* JADX WARNING: Unknown top exception splitter block from list: {B:28:0x00a2=Splitter:B:28:0x00a2, B:18:0x0045=Splitter:B:18:0x0045} */
                public Void then(Task<Void> task) {
                    try {
                        if (CommonHelper.checkInternetConnection(CommonFrameworkImpl.getContext()) || CommonFrameworkImpl.isTest) {
                            SharedPreferences demoPref = CommonFrameworkImpl.getContext().getSharedPreferences("demoForTracking", 0);
                            if (CommonFrameworkImpl.localDemographicInfo == null || CommonFrameworkImpl.localDemographicInfo.size() <= 0) {
                                List<Pair<String, String>> demos = RequestParameter.getATRequestParameter(CommonFrameworkImpl.getContext()).getDemoInfo();
                                if (demos != null && demos.size() > 0) {
                                    CommonFrameworkImpl.httpManager.demographicCallForADBrix(CommonFrameworkImpl.parameter, CommonFrameworkImpl.getContext());
                                }
                            } else {
                                Editor demoEditor = demoPref.edit();
                                for (int i = 0; i < CommonFrameworkImpl.localDemographicInfo.size(); i++) {
                                    Pair<String, String> demo = CommonFrameworkImpl.localDemographicInfo.get(i);
                                    demoEditor.putString((String) demo.first, (String) demo.second);
                                }
                                demoEditor.apply();
                                TaskUtils.wait(Task.delay(500), 2000, TimeUnit.MILLISECONDS);
                                CommonFrameworkImpl.localDemographicInfo.clear();
                            }
                        }
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    } catch (OutOfMemoryError Err) {
                    }
                    return null;
                }
            }, (Executor) InternalAction.NETWORK_EXECUTOR);
            if (session_stack_count == 0) {
                activity(SettingsJsonConstants.SESSION_KEY, "end", Long.toString(endSessionParam), null, getContext());
            }
            if (this.commonLiveOpsCallbackListener != null) {
                this.commonLiveOpsCallbackListener.onEndSession(getContext());
            }
            if (getExtendedActivityListener() != null) {
                for (ExtendedCommonActivityListener item : getExtendedActivityListener()) {
                    item.onEndSession(getContext(), session_stack_count);
                }
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public void flush() {
        try {
            if (parameter.getADBrixUserNo() >= 1) {
                if (getContext() == null) {
                    Log.e(IgawConstant.QA_TAG, "ADBrixManager > application context error, please check context value. startSession() should be called at least once.");
                    return;
                }
                IgawLogger.Logging(getContext(), IgawConstant.QA_TAG, "ADBrixManager > flush started", 3, false);
                httpManager = getHttpManager(getContext());
                InternalAction.getInstance().trackingForAdbrixCall(getContext(), isTest, httpManager, "n/a", "n/a", 0);
            }
        } catch (Exception e) {
            Log.e(IgawConstant.QA_TAG, "FLUSH ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void aprt(String name) {
        activity("ret", name, null, null, getContext());
    }

    public void aprt(String name, String param) {
        activity("ret", name, param, null, getContext());
    }

    public void setAge(final int age) {
        if (getContext() == null) {
            Log.e(IgawConstant.QA_TAG, "ADBrixManager > application context error, please check context value. startSession() should be called at least once.");
        } else {
            new Thread(new Runnable() {
                public void run() {
                    try {
                        CommonFrameworkImpl.this.save_demographic("age", Integer.toString(age));
                        CommonFrameworkImpl.this.setAgeAdpopcorn(Integer.toString(age));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }
    }

    public void setGender(final int gender) {
        if (getContext() == null) {
            Log.e(IgawConstant.QA_TAG, "ADBrixManager > application context error, please check context value. startSession() should be called at least once.");
        } else {
            new Thread(new Runnable() {
                public void run() {
                    CommonFrameworkImpl.this.save_demographic("gender", Integer.toString(gender));
                    CommonFrameworkImpl.this.setGenderAdpopcorn(Integer.toString(gender));
                }
            }).start();
        }
    }

    public void setUserId(String userId) {
        String usn = userId;
        if (getContext() == null) {
            Log.e(IgawConstant.QA_TAG, "setUserId: ADBrixManager > application context error, please check context value. startSession() should be called at least once.");
            return;
        }
        if (userId == null || userId.equals("")) {
            usn = "";
        }
        final String _usn = usn;
        new Thread(new Runnable() {
            public void run() {
                CommonFrameworkImpl.this.save_demographic(DemographicDAO.KEY_USN, _usn);
                if (!_usn.equals("")) {
                    CommonFrameworkImpl.this.setUsnAdpopcorn(_usn);
                }
                CommonFrameworkImpl.this.setUsnLiveOps(CommonFrameworkImpl.getContext(), _usn);
            }
        }).start();
    }

    public void setCommonAPCallbackListener(ICommonAPCallbackListener listener) {
        this.commonAPCallbackListener = listener;
    }

    public void setCommonLiveOpsCallbackListener(ICommonLiveOpsCallbackListener listener) {
        this.commonLiveOpsCallbackListener = listener;
    }

    /* access modifiers changed from: protected */
    public void save_demographic(String key, String value) {
        try {
            if (getContext() == null) {
                if (localDemographicInfo == null) {
                    localDemographicInfo = new ArrayList();
                }
                localDemographicInfo.add(new Pair(key, value));
                Log.i(IgawConstant.QA_TAG, "Null context on save_demographic, pls call startSession first");
                return;
            }
            IgawLogger.Logging(getContext(), IgawConstant.QA_TAG, "ADBrixManager > save_demographic() >> key " + key + " value : " + value, 3);
            Editor persistantDemoEditor = getContext().getSharedPreferences("persistantDemoForTracking", 0).edit();
            persistantDemoEditor.putString(key, value);
            persistantDemoEditor.commit();
            Editor demoEditor = getContext().getSharedPreferences("demoForTracking", 0).edit();
            demoEditor.putString(key, value);
            demoEditor.commit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /* access modifiers changed from: private */
    public void setUsnLiveOps(Context context, String userId) {
        if (this.commonLiveOpsCallbackListener != null) {
            this.commonLiveOpsCallbackListener.OnCommonSetUsn(context, userId);
        }
    }

    /* access modifiers changed from: private */
    public void setUsnAdpopcorn(String userId) {
        Editor editor = getContext().getSharedPreferences("adpopcorn_parameter", 0).edit();
        editor.putString("adpopcorn_sdk_usn", userId);
        editor.commit();
        if (this.commonAPCallbackListener != null) {
            this.commonAPCallbackListener.OnCommonSetUsn(userId);
        }
    }

    /* access modifiers changed from: private */
    public void setGenderAdpopcorn(String gender) {
        Editor editor = getContext().getSharedPreferences("adpopcorn_parameter", 0).edit();
        editor.putString("adpopcorn_sdk_gender", gender);
        editor.commit();
    }

    /* access modifiers changed from: private */
    public void setAgeAdpopcorn(String age) {
        Editor editor = getContext().getSharedPreferences("adpopcorn_parameter", 0).edit();
        editor.putString("adpopcorn_sdk_age", age);
        editor.commit();
    }

    @Deprecated
    public void viral(String name) {
        activity("viral", name, null, null, getContext());
    }

    @Deprecated
    public void viral(String name, String param) {
        activity("viral", name, param, null, getContext());
    }

    @Deprecated
    public void error(String errorName, String detail) {
        activity("error", errorName, detail, null, getContext());
    }

    @Deprecated
    public void custom(String name) {
        activity("custom", name, null, null, getContext());
    }

    @Deprecated
    public void custom(String name, String param) {
        activity("custom", name, param, null, getContext());
    }

    public void custom(String group, String name, String param) {
        activity(group, name, param, null, getContext());
    }

    public void setClientRewardEventListener(IgawRewardItemEventListener listener) {
        clientRewardlistener = listener;
    }

    public static IgawRewardItemEventListener getClientRewardListener() {
        return clientRewardlistener;
    }

    public void onReceiveReferral(Context context) {
        onReceiveReferral(context, null);
    }

    public void onReceiveReferral(final Context context, String params) {
        try {
            if (getContext() == null) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > application context error, please check context value. startSession() should be called at least once.", 0, false);
                return;
            }
            initAppInfo(context);
            if (parameter == null) {
                parameter = RequestParameter.getATRequestParameter(getContext());
            }
            if (parameter.getReferralKey() < 0 || parameter.getADBrixUserNo() < 1 || ReferralInfoDAO.getOnReceiveReferralFlag(getContext())) {
                new Thread(new Runnable() {
                    public void run() {
                        CommonFrameworkImpl.this.getHttpManager(CommonFrameworkImpl.getContext()).CPI_referrerCallForADBrix(CommonFrameworkImpl.parameter, CommonFrameworkImpl.getContext(), ActivityInfoDAO.getActivityInfoForReferral(context));
                    }
                }).start();
            }
            navigateDeeplinkActivity(context, params);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void navigateDeeplinkActivity(Context context, String params) {
        String[] split;
        if (params != null) {
            try {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "deeplink referral param : " + params, 2, true);
                Intent i = new Intent();
                i.setAction("android.intent.action.VIEW");
                i.addCategory("android.intent.category.BROWSABLE");
                for (String param : params.split("&")) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "deeplink splitted param : " + param, 2, true);
                    String[] kv = param.split("=");
                    if (kv.length == 2) {
                        if (kv[0].equals("igaw_intent")) {
                            try {
                                i.setData(Uri.parse(Uri.decode(kv[1])));
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "deeplink data : " + i.getDataString(), 2, true);
                            } catch (Exception e) {
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "deeplink data error : " + e.toString(), 0, true);
                            }
                        } else {
                            i.putExtra(kv[0], kv[1]);
                        }
                    }
                }
                if (receiverComponents != null && receiverComponents.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "deeplink receiverComponents size : " + receiverComponents.size(), 2, true);
                    for (String item : receiverComponents) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, String.format("deeplink intent broadcasting : %s << %s", new Object[]{item, params}), 2, false);
                        String[] splitted = item.split(";");
                        if (splitted != null && splitted.length == 2) {
                            i.setComponent(new ComponentName(splitted[0], splitted[1]));
                            appContext.startActivity(i);
                        }
                    }
                } else if (i.getData() != null) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "deeplink intent broadcasting", 2, true);
                    if (appContext instanceof Activity) {
                        ((Activity) appContext).startActivity(i);
                    } else {
                        appContext.startActivity(i);
                    }
                }
            } catch (Exception e2) {
                try {
                    e2.printStackTrace();
                } catch (Exception e3) {
                    e3.printStackTrace();
                }
            }
        }
    }

    private void restoreActivityForNullContext(Context context) {
        try {
            if (restoreForNullContext != null && restoreForNullContext.size() > 0) {
                for (JSONObject item : restoreForNullContext) {
                    String group = null;
                    String activity = null;
                    String param = null;
                    String createdAt = null;
                    if (item.has("group")) {
                        group = item.getString("group");
                    }
                    if (item.has("activity")) {
                        activity = item.getString("activity");
                    }
                    if (item.has("param")) {
                        param = item.getString("param");
                    }
                    if (item.has("createdAt")) {
                        createdAt = item.getString("createdAt");
                    }
                    activity(group, activity, param, createdAt, context);
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager >restore activity for null context : " + group + " / " + activity + " / " + param + "/" + createdAt, 3, false);
                }
                restoreForNullContext.clear();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void addIntentReceiver(String componentName) {
        try {
            if (!receiverComponents.contains(componentName)) {
                receiverComponents.add(componentName);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void removeIntentReceiver(String componentName) {
        try {
            receiverComponents.remove(componentName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void clearIntentReceiver() {
        try {
            receiverComponents.clear();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void resendDeeplinkConversion(final Context context) {
        Task.delay(3000).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Void, Void>() {
            /* JADX WARNING: Code restructure failed: missing block: B:35:0x00f5, code lost:
                r4 = move-exception;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:38:?, code lost:
                android.util.Log.e(com.igaworks.core.IgawConstant.QA_TAG, "DeeplinkReEngagementConversion Resend Error: " + r4.getMessage());
             */
            /* JADX WARNING: Code restructure failed: missing block: B:39:0x0111, code lost:
                r0 = move-exception;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:40:0x0112, code lost:
                android.util.Log.w(com.igaworks.core.IgawConstant.QA_TAG, "ReSendDeeplinkConversion >> OOM Error: " + r0.getMessage());
             */
            /* JADX WARNING: Failed to process nested try/catch */
            /* JADX WARNING: Removed duplicated region for block: B:39:0x0111 A[ExcHandler: OutOfMemoryError (r0v0 'Err' java.lang.OutOfMemoryError A[CUSTOM_DECLARE]), Splitter:B:7:0x003c] */
            public Void then(Task<Void> task) {
                try {
                    DeeplinkConversionRetryDAO dao = DeeplinkConversionRetryDAO.getDAO(context);
                    ArrayList<DeeplinkConversionItem> conversionItems = dao.getRetryConversions(context);
                    if (conversionItems != null && conversionItems.size() > 0) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "retry deeplink onstartSession - count : " + conversionItems.size(), 3, true);
                        CommonFrameworkImpl.httpManager.conversionForDeeplink(CommonFrameworkImpl.parameter, context, conversionItems);
                    }
                    try {
                        ArrayList<DeeplinkReEngagementConversion> dlReEngagementList = dao.getRetryReEngagementConversions(context);
                        if (dlReEngagementList != null && dlReEngagementList.size() > 0) {
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "DeeplinkReEngagementConversion : retry deeplink onstartSession - count : " + dlReEngagementList.size(), 3, true);
                            Iterator<DeeplinkReEngagementConversion> it = dlReEngagementList.iterator();
                            while (it.hasNext()) {
                                CommonFrameworkImpl.httpManager.ReEngagementConversion(CommonFrameworkImpl.parameter, context, it.next());
                                Thread.sleep(500);
                            }
                        }
                    } catch (Exception e) {
                        Log.e(IgawConstant.QA_TAG, "DeeplinkReEngagementConversion Resend Error: " + e.getMessage());
                    } catch (OutOfMemoryError Err) {
                    }
                    ArrayList<DeeplinkReEngagementConversion> thirdPartyConversions = dao.getRetryThirdPartyConversions(context);
                    if (thirdPartyConversions != null && thirdPartyConversions.size() > 0) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ThirdParty Conversion : retry deeplink onstartSession - count : " + thirdPartyConversions.size(), 3, true);
                        Iterator<DeeplinkReEngagementConversion> it2 = thirdPartyConversions.iterator();
                        while (it2.hasNext()) {
                            CommonFrameworkImpl.httpManager.ThirdPartyConversion(CommonFrameworkImpl.parameter, context, it2.next());
                            Thread.sleep(500);
                        }
                    }
                } catch (Exception ex) {
                    ex.printStackTrace();
                } catch (OutOfMemoryError Err2) {
                }
                return null;
            }
        }, (Executor) InternalAction.NETWORK_EXECUTOR);
    }

    public void deeplinkConversion(final Activity activity, final boolean callFromAPI) {
        Task.forResult(null).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Object, Void>() {
            /* JADX WARNING: Code restructure failed: missing block: B:121:0x0363, code lost:
                r24 = move-exception;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:123:?, code lost:
                r24.printStackTrace();
             */
            /* JADX WARNING: Code restructure failed: missing block: B:153:0x044d, code lost:
                if (r33.booleanValue() == false) goto L_0x044f;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:157:0x0457, code lost:
                if (r35.booleanValue() == false) goto L_0x0463;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:161:0x0461, code lost:
                if (r34.booleanValue() != false) goto L_0x0463;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:162:0x0463, code lost:
                com.igaworks.impl.CommonFrameworkImpl.parameter.setProcessedConversions(r6);
             */
            /* JADX WARNING: Code restructure failed: missing block: B:163:0x0472, code lost:
                if (com.igaworks.impl.CommonFrameworkImpl.parameter.getADBrixUserNo() <= -1) goto L_0x04f7;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:165:0x0478, code lost:
                if (r38 <= -1) goto L_0x04f7;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:166:0x047a, code lost:
                r21 = new org.json.JSONObject();
                r21.put("session_no", r38);
                r21.put("conversion_key", r6);
                r21.put("deeplink_uri", r22);
                r21.put("sub_conversion_key", r40);
                r46.this$0.getHttpManager(com.igaworks.impl.CommonFrameworkImpl.getContext()).ReEngagementConversion(com.igaworks.impl.CommonFrameworkImpl.parameter, com.igaworks.impl.CommonFrameworkImpl.getContext(), new com.igaworks.model.DeeplinkReEngagementConversion(-1, r6, r21.toString(), 0, 0));
             */
            /* JADX WARNING: Code restructure failed: missing block: B:167:0x04c9, code lost:
                r30 = move-exception;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:170:?, code lost:
                android.util.Log.e(com.igaworks.core.IgawConstant.QA_TAG, "ReEngagementConversion Error: " + r30.getMessage());
             */
            /* JADX WARNING: Code restructure failed: missing block: B:173:?, code lost:
                com.igaworks.core.IgawLogger.Logging(com.igaworks.impl.CommonFrameworkImpl.getContext(), com.igaworks.core.IgawConstant.QA_TAG, "Skip ReEngagement Deeplink", 2, true);
             */
            /* JADX WARNING: Code restructure failed: missing block: B:69:0x0204, code lost:
                r15 = move-exception;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:70:0x0205, code lost:
                android.util.Log.w(com.igaworks.core.IgawConstant.QA_TAG, "OOM Error: " + r15.getMessage());
             */
            /* JADX WARNING: Code restructure failed: missing block: B:72:0x0223, code lost:
                r29 = move-exception;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:74:?, code lost:
                r29.printStackTrace();
             */
            /* JADX WARNING: Code restructure failed: missing block: B:76:0x022a, code lost:
                r6 = -1;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:78:0x022e, code lost:
                r7 = null;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:80:0x0232, code lost:
                r33 = null;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:82:0x0237, code lost:
                r35 = null;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:84:0x023c, code lost:
                r34 = null;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:86:0x0240, code lost:
                r38 = -1;
             */
            /* JADX WARNING: Code restructure failed: missing block: B:88:0x0244, code lost:
                r40 = "";
             */
            /* JADX WARNING: Failed to process nested try/catch */
            /* JADX WARNING: Removed duplicated region for block: B:69:0x0204 A[ExcHandler: OutOfMemoryError (r15v0 'Err' java.lang.OutOfMemoryError A[CUSTOM_DECLARE]), Splitter:B:29:0x010b] */
            public Void then(Task<Object> task) {
                Uri iUri;
                boolean z;
                ArrayList<DeeplinkConversionItem> conversionItems = null;
                try {
                    Intent i = activity.getIntent();
                    if (i != null) {
                        CommonFrameworkImpl.setContext(activity.getApplicationContext());
                        CommonFrameworkImpl.this.initAppInfo(CommonFrameworkImpl.getContext());
                        CommonFrameworkImpl.parameter = RequestParameter.getATRequestParameter(CommonFrameworkImpl.getContext());
                        Uri iUri2 = i.getData();
                        if (iUri2 == null || !iUri2.toString().contains("?")) {
                            if (callFromAPI) {
                                IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "Deeplink API: bundle and data are null", 2, false);
                            } else {
                                IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "OnstartSession deeplink : bundle and data are null", 2, false);
                            }
                            return null;
                        }
                        String uriStr = iUri2.toString();
                        String deeplink = uriStr.substring(0, uriStr.indexOf(63));
                        IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "uriStr from intent data: " + uriStr, 3, true);
                        try {
                            iUri = Uri.parse("http://igaworks.com" + uriStr.substring(uriStr.indexOf(63), uriStr.length()));
                        } catch (Exception e) {
                            iUri = null;
                        } catch (OutOfMemoryError Err) {
                        }
                        if (callFromAPI) {
                            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "Deeplink API >> iUri is null >>" + (iUri == null), 2, false);
                        } else {
                            Context context = CommonFrameworkImpl.getContext();
                            StringBuilder sb = new StringBuilder("OnStartSession: deeplink >> iUri is null >>");
                            if (iUri == null) {
                                z = true;
                            } else {
                                z = false;
                            }
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, sb.append(z).toString(), 2, false);
                        }
                        try {
                            URL url = new URL(iUri.toString());
                            Map<String, String> params = CommonFrameworkImpl.this.splitQuery(url);
                            if (deeplink != null && deeplink.length() > 0) {
                                String url_without_Ck = CommonFrameworkImpl.this.makeNewDeeplinkWithoutCk(deeplink, params);
                                activity.getIntent().setData(Uri.parse(url_without_Ck));
                                if (CommonFrameworkImpl.isTest) {
                                    Log.i(IgawConstant.QA_TAG, "New URI: " + url_without_Ck);
                                }
                            }
                            if (iUri != null) {
                                String deeplink_uri = uriStr;
                                int conversionKey = Integer.parseInt(iUri.getQueryParameter("ck"));
                                String commerceClickID = iUri.getQueryParameter("cid");
                                Boolean igaw_deeplink_cvr = Boolean.valueOf(Boolean.parseBoolean(iUri.getQueryParameter("igaw_deeplink_cvr")));
                                Boolean isFacebookCpi = Boolean.valueOf(Boolean.parseBoolean(iUri.getQueryParameter("isFacebookCpi")));
                                Boolean igaw_eng = Boolean.valueOf(Boolean.parseBoolean(iUri.getQueryParameter("igaw_eng")));
                                long session_no = Long.parseLong(iUri.getQueryParameter("sn"));
                                String sub_conversion_key = iUri.getQueryParameter("sub_referral");
                                if (conversionKey < 0) {
                                    return null;
                                }
                                ArrayList<String> AllowDuplicationList = CommonFrameworkImpl.parameter.getAllowDuplicationConversions();
                                if (AllowDuplicationList != null && AllowDuplicationList.contains(new StringBuilder(String.valueOf(conversionKey)).toString())) {
                                    Iterator<String> it = AllowDuplicationList.iterator();
                                    while (it.hasNext()) {
                                        String item = it.next();
                                        if (item.startsWith(new StringBuilder(String.valueOf(conversionKey)).append(";").toString())) {
                                            CommonFrameworkImpl.parameter.removeRetainedConversionCache(Integer.parseInt(item.substring(item.indexOf(";") + 1)));
                                        }
                                    }
                                }
                                if (!CommonFrameworkImpl.TempProcessedConversionList.contains(Integer.valueOf(conversionKey))) {
                                    CommonFrameworkImpl.TempProcessedConversionList.add(Integer.valueOf(conversionKey));
                                    Task.delay(2500).continueWith(new Continuation<Void, Void>() {
                                        public Void then(Task<Void> task) {
                                            try {
                                                if (CommonFrameworkImpl.TempProcessedConversionList != null && CommonFrameworkImpl.TempProcessedConversionList.size() > 0) {
                                                    CommonFrameworkImpl.TempProcessedConversionList.clear();
                                                }
                                            } catch (Exception ex) {
                                                ex.printStackTrace();
                                            } catch (OutOfMemoryError Err) {
                                                Log.w(IgawConstant.QA_TAG, "Clear TempProcessedConversionList>> OOM Error: " + Err.getMessage());
                                            }
                                            return null;
                                        }
                                    });
                                    Log.d(IgawConstant.QA_TAG, String.format("Deeplink conversion >> ck = %s; cid = %s; igaw_deeplink_cvr = %s ; session_no = %s, sub_conversion_key = %s, isFacebookCpi = %s, igaw_eng = %s ", new Object[]{String.valueOf(conversionKey), commerceClickID, igaw_deeplink_cvr, Long.valueOf(session_no), sub_conversion_key, String.valueOf(isFacebookCpi), String.valueOf(igaw_eng)}));
                                    IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "deeplink conversion >> query string extra : " + iUri.getQuery(), 2, true);
                                    if (isFacebookCpi != null && isFacebookCpi.booleanValue()) {
                                        if (CommonFrameworkImpl.parameter.getProcessedConversions().contains(Integer.valueOf(conversionKey))) {
                                            Log.i(IgawConstant.QA_TAG, "Deeplinking: Thirdparty conversion key: " + conversionKey + " counted by Igaworks already.");
                                            return null;
                                        }
                                        CommonFrameworkImpl.parameter.setProcessedConversions(conversionKey);
                                    }
                                    if (CommonFrameworkImpl.parameter.getADBrixUserNo() <= -1 || session_no <= 0) {
                                        IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "Skip Legacy deeplink", 2, true);
                                    } else {
                                        if (!CommonFrameworkImpl.processedClickID.contains(new StringBuilder(String.valueOf(conversionKey)).append(";").append(commerceClickID).toString())) {
                                            if (commerceClickID != null && commerceClickID.length() > 0 && conversionKey > -1) {
                                                if (0 == 0) {
                                                    conversionItems = new ArrayList<>();
                                                }
                                                conversionItems.add(new DeeplinkConversionItem(-1, conversionKey, commerceClickID, iUri.getQuery(), 0, 0));
                                            }
                                            CommonFrameworkImpl.processedClickID.add(new StringBuilder(String.valueOf(conversionKey)).append(";").append(commerceClickID).toString());
                                        }
                                        if (conversionItems != null && conversionItems.size() > 0) {
                                            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "deeplink Conversion - count : " + conversionItems.size(), 3, true);
                                            CommonFrameworkImpl.httpManager = CommonFrameworkImpl.this.getHttpManager(CommonFrameworkImpl.getContext());
                                            CommonFrameworkImpl.httpManager.conversionForDeeplink(CommonFrameworkImpl.parameter, CommonFrameworkImpl.getContext(), conversionItems);
                                        }
                                    }
                                    if (conversionKey > 0 && igaw_deeplink_cvr != null) {
                                    }
                                    if (conversionKey > 0) {
                                        if (isFacebookCpi != null) {
                                        }
                                    }
                                    if (conversionKey > 0) {
                                        if (igaw_eng != null) {
                                        }
                                    }
                                } else {
                                    Log.d(IgawConstant.QA_TAG, "Deeplink conversionKey " + conversionKey + " exists in cache >> Skip");
                                    return null;
                                }
                            }
                        } catch (Exception e2) {
                            e2.printStackTrace();
                        } catch (OutOfMemoryError Err2) {
                        }
                    }
                } catch (Exception e3) {
                    IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "@deeplinkConversion API Error: " + e3.toString(), 0, false);
                } catch (OutOfMemoryError Err22) {
                }
                return null;
            }
        }, (Executor) InternalAction.NETWORK_EXECUTOR);
    }

    public void setDeferredLinkListener(Context context, DeferredLinkListener listener) {
        if (RequestParameter.getATRequestParameter(context).getADBrixUserNo() == -1) {
            getHttpManager(context).setDeferredLinkListener(context, listener);
        } else {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "Skip setDeferredLinkListener >> it is called after sdk gets Adbrix information", 2, true);
        }
    }

    public void setReferralUrlForFacebook(final Context context, final String deeplinkStr) {
        setContext(context);
        initAppInfo(context);
        parameter = RequestParameter.getATRequestParameter(context);
        InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
            public void run() {
                Uri iUri;
                int conversionKey;
                String commerceClickID;
                Boolean igaw_deeplink_cvr;
                Boolean isFacebookCpi;
                long session_no;
                String sub_conversion_key;
                boolean sentDeeplink = true;
                try {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "setReferralUrl: deeplinkStr >> " + deeplinkStr, 3, false);
                    if (deeplinkStr == null || ((!deeplinkStr.contains("ref.ad-brix.com/v1/referrallink") && !deeplinkStr.contains("ref.ad-brix.com/adbrix/qa/referrallink")) || !deeplinkStr.contains("Deeplink=true") || !deeplinkStr.contains("ck="))) {
                        try {
                            iUri = Uri.parse("http://igaworks.com" + deeplinkStr.substring(deeplinkStr.indexOf(63), deeplinkStr.length()));
                        } catch (Exception e) {
                            iUri = null;
                        }
                    } else {
                        sentDeeplink = false;
                        try {
                            Uri targetUri = Uri.parse(deeplinkStr);
                            String conversionKey2 = targetUri.getQueryParameter("ck");
                            String sck = "";
                            if (deeplinkStr.contains("sub_referral=")) {
                                sck = targetUri.getQueryParameter("sub_referral");
                            }
                            HashMap hashMap = new HashMap();
                            hashMap.put("ck", conversionKey2);
                            if (sck != null && !sck.equals("")) {
                                hashMap.put("sub_referral", sck);
                            }
                            hashMap.put("isFacebookCpi", ServerProtocol.DIALOG_RETURN_SCOPES_TRUE);
                            Builder b = Uri.parse("http://igaworks.com").buildUpon();
                            for (Entry<String, String> entry : hashMap.entrySet()) {
                                b.appendQueryParameter(entry.getKey(), entry.getValue());
                            }
                            iUri = Uri.parse(b.build().toString());
                        } catch (Exception e_url) {
                            Log.d(IgawConstant.QA_TAG, "setReferralUrl >> " + e_url.getMessage());
                            iUri = null;
                        }
                    }
                    if (iUri != null) {
                        try {
                            conversionKey = Integer.parseInt(iUri.getQueryParameter("ck"));
                        } catch (Exception e2) {
                            conversionKey = -1;
                        }
                        try {
                            commerceClickID = iUri.getQueryParameter("cid");
                        } catch (Exception e3) {
                            commerceClickID = null;
                        }
                        try {
                            igaw_deeplink_cvr = Boolean.valueOf(Boolean.parseBoolean(iUri.getQueryParameter("igaw_deeplink_cvr")));
                        } catch (Exception e4) {
                            igaw_deeplink_cvr = null;
                        }
                        try {
                            isFacebookCpi = Boolean.valueOf(Boolean.parseBoolean(iUri.getQueryParameter("isFacebookCpi")));
                        } catch (Exception e5) {
                            isFacebookCpi = null;
                        }
                        try {
                            session_no = Long.parseLong(iUri.getQueryParameter("sn"));
                        } catch (Exception e6) {
                            session_no = -1;
                        }
                        try {
                            sub_conversion_key = iUri.getQueryParameter("sub_referral");
                        } catch (Exception e7) {
                            sub_conversion_key = "";
                        }
                        if (conversionKey >= 0 && isFacebookCpi != null) {
                            if (isFacebookCpi.booleanValue()) {
                                ArrayList<String> AllowDuplicationList = CommonFrameworkImpl.parameter.getAllowDuplicationConversions();
                                if (AllowDuplicationList != null && AllowDuplicationList.contains(new StringBuilder(String.valueOf(conversionKey)).toString())) {
                                    Iterator<String> it = AllowDuplicationList.iterator();
                                    while (it.hasNext()) {
                                        String item = it.next();
                                        if (item.startsWith(new StringBuilder(String.valueOf(conversionKey)).append(";").toString())) {
                                            try {
                                                CommonFrameworkImpl.parameter.removeRetainedConversionCache(Integer.parseInt(item.substring(item.indexOf(";") + 1)));
                                            } catch (Exception e8) {
                                                e8.printStackTrace();
                                            }
                                        }
                                    }
                                }
                                if (!CommonFrameworkImpl.TempProcessedConversionList.contains(Integer.valueOf(conversionKey))) {
                                    CommonFrameworkImpl.TempProcessedConversionList.add(Integer.valueOf(conversionKey));
                                    Task.delay(5000).continueWith(new Continuation<Void, Void>() {
                                        public Void then(Task<Void> task) throws Exception {
                                            try {
                                                if (CommonFrameworkImpl.TempProcessedConversionList != null && CommonFrameworkImpl.TempProcessedConversionList.size() > 0) {
                                                    CommonFrameworkImpl.TempProcessedConversionList.clear();
                                                }
                                            } catch (Exception ex) {
                                                ex.printStackTrace();
                                            } catch (OutOfMemoryError Err) {
                                                Log.w(IgawConstant.QA_TAG, "SetReferrealUrl >> OOM Error: " + Err.getMessage());
                                            }
                                            return null;
                                        }
                                    });
                                    try {
                                        Log.d(IgawConstant.QA_TAG, String.format("setReferralUrl >> ck = %s; cid = %s; igaw_deeplink_cvr = %s ; session_no = %s, sub_conversion_key = %s, isFacebookCpi = %s ", new Object[]{String.valueOf(conversionKey), commerceClickID, igaw_deeplink_cvr, Long.valueOf(session_no), sub_conversion_key, String.valueOf(isFacebookCpi)}));
                                        if (CommonFrameworkImpl.parameter.getProcessedConversions().contains(Integer.valueOf(conversionKey))) {
                                            Log.i(IgawConstant.QA_TAG, "setReferralUrl: Thirdparty conversion key: " + conversionKey + " counted by Igaworks.");
                                            return;
                                        }
                                        CommonFrameworkImpl.parameter.setProcessedConversions(conversionKey);
                                        JSONObject applink_deeplink_info = new JSONObject();
                                        applink_deeplink_info.put("session_no", session_no);
                                        applink_deeplink_info.put("conversion_key", conversionKey);
                                        if (sentDeeplink) {
                                            applink_deeplink_info.put("deeplink_uri", deeplinkStr);
                                        } else {
                                            applink_deeplink_info.put("tracking_url", deeplinkStr);
                                        }
                                        applink_deeplink_info.put("sub_conversion_key", sub_conversion_key);
                                        CommonFrameworkImpl.this.getHttpManager(context).ThirdPartyConversion(CommonFrameworkImpl.parameter, context, new DeeplinkReEngagementConversion(-1, conversionKey, applink_deeplink_info.toString(), 0, 0));
                                        return;
                                    } catch (Exception e9) {
                                        return;
                                    }
                                } else {
                                    Log.d(IgawConstant.QA_TAG, "setReferralUrl " + conversionKey + " exists in cache >> Skip");
                                    return;
                                }
                            }
                        }
                        Log.i(IgawConstant.QA_TAG, "setReferralUrl >> invalid parameters");
                    }
                } catch (Exception e10) {
                    e10.printStackTrace();
                }
            }
        });
    }

    private void dailyRetentionEvent(Context context) {
        String lastDailyRentionDate = AppImpressionDAO.getLastDailyRentionDate(context);
        try {
            if (!lastDailyRentionDate.equals("")) {
                Calendar now = Calendar.getInstance();
                now.add(6, -1);
                if (lastDailyRentionDate.substring(0, 10).equals(AdbrixDB_v2.DB_DATE_FORMAT.format(now.getTime()).substring(0, 10))) {
                    activity(SettingsJsonConstants.SESSION_KEY, "retention", null, null, getContext());
                }
            } else {
                activity(SettingsJsonConstants.SESSION_KEY, "retention", null, null, getContext());
            }
        } catch (Exception e) {
            Log.e(IgawConstant.QA_TAG, "dailyRetentionEvent Error: " + e.getMessage());
        } finally {
            AppImpressionDAO.setLastDailyRentionDate(context);
        }
    }

    /* access modifiers changed from: private */
    public Map<String, String> splitQuery(URL url) throws UnsupportedEncodingException {
        String[] pairs;
        Map<String, String> query_pairs = new LinkedHashMap<>();
        for (String pair : url.getQuery().split("&")) {
            int idx = pair.indexOf("=");
            query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }
        return query_pairs;
    }

    /* access modifiers changed from: private */
    public String makeNewDeeplinkWithoutCk(String deeplink, Map<String, String> parameters) {
        Builder b = Uri.parse(deeplink).buildUpon();
        for (Entry<String, String> entry : parameters.entrySet()) {
            String key = entry.getKey();
            if (key != null && !key.equals("ck") && !key.equals("referrer")) {
                b.appendQueryParameter(entry.getKey(), entry.getValue());
            }
        }
        return b.build().toString();
    }

    public static void sendCrashReport(List<JSONObject> err) {
        httpManager.reportingCrash(parameter, getContext(), err);
    }
}