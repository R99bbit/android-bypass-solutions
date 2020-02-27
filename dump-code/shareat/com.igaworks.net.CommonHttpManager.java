package com.igaworks.net;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.net.Uri;
import android.util.Log;
import com.igaworks.core.AESGetTrackParam;
import com.igaworks.core.AdvertisingIdClient.ADIDCallbackListener;
import com.igaworks.core.AdvertisingIdClient.AdInfo;
import com.igaworks.core.DeviceIDManger;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;
import com.igaworks.dao.ActivityInfoDAO;
import com.igaworks.dao.AppImpressionDAO;
import com.igaworks.dao.CrashDAO;
import com.igaworks.dao.DeeplinkConversionRetryDAO;
import com.igaworks.dao.LocalDemograhpicDAO;
import com.igaworks.dao.ReferralInfoDAO;
import com.igaworks.dao.tracking.TrackingActivityModel;
import com.igaworks.dao.tracking.TrackingActivitySQLiteDB;
import com.igaworks.dao.tracking.TrackingActivitySQLiteOpenHelper;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.impl.InternalAction;
import com.igaworks.interfaces.CommonActivityListener;
import com.igaworks.interfaces.CommonInterface;
import com.igaworks.interfaces.DeferredLinkListener;
import com.igaworks.interfaces.HttpCallbackListener;
import com.igaworks.model.DeeplinkConversionItem;
import com.igaworks.model.DeeplinkReEngagementConversion;
import com.igaworks.util.CommonHelper;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.Task;
import com.kakao.auth.helper.ServerProtocol;
import io.fabric.sdk.android.services.events.EventsFilesManager;
import java.lang.ref.WeakReference;
import java.net.SocketTimeoutException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map.Entry;
import java.util.TimeZone;
import java.util.concurrent.Executor;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class CommonHttpManager extends HttpManager {
    public static final int API1 = 1;
    public static final int API2 = 2;
    public static final int COMMON_CALLBACK_REFERRAL = 1;
    public static final String ERR_MSG = "errMsg";
    /* access modifiers changed from: private */
    public static boolean isReturnDL = false;
    /* access modifiers changed from: private */
    public static DeferredLinkListener mDeferredLinkListener;
    private static boolean onCPIReferrerCall = false;
    private static boolean onReferrerCall = false;

    public void switchAPI(int apiNo) {
    }

    public void normal_referrerCallForADBrix(final RequestParameter parameter, final Context context, final ArrayList<String> activity_info_list) {
        if (getOnReferrerCall()) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "referrerCallForADBrix > referral call already sent.", 3);
            return;
        }
        setOnReferrerCall(true);
        try {
            DeviceIDManger.getInstance(context).getAndroidADID(context, new ADIDCallbackListener() {
                public void onResult(AdInfo adInfo) {
                    boolean isLimitAdTrackingEnabled;
                    String url = CommonHttpManager.this.REFERRER_REQUEST_URL_FOR_ADBrix;
                    try {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "normal referrerCallForADBrix", 3, false);
                        RequestParameter requestParameter = parameter;
                        Context context = context;
                        ArrayList arrayList = activity_info_list;
                        String id = adInfo == null ? "" : adInfo.getId();
                        if (adInfo == null) {
                            isLimitAdTrackingEnabled = false;
                        } else {
                            isLimitAdTrackingEnabled = adInfo.isLimitAdTrackingEnabled();
                        }
                        String param = AESGetTrackParam.encrypt_hashkey(requestParameter.getReferrerTrackingParameter(context, arrayList, null, id, isLimitAdTrackingEnabled), parameter.getHashkey());
                        boolean isAdbrixSyn = AppImpressionDAO.getSynAdbrix(CommonFrameworkImpl.getContext());
                        if (parameter.getReferralKey() < 1 || !isAdbrixSyn) {
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "normal referrerCallForADBrix > referral call send.", 3, false);
                            HashMap<String, String> paramValuePair = new HashMap<>();
                            paramValuePair.put("k", new StringBuilder(String.valueOf(parameter.getAppkey())).toString());
                            paramValuePair.put("j", param);
                            Context context2 = context;
                            final Context context3 = context;
                            final ArrayList arrayList2 = activity_info_list;
                            final RequestParameter requestParameter2 = parameter;
                            WeakReference<Thread> threadW = new WeakReference<>(new HttpsUrlConnectionThread(context2, 1, url, paramValuePair, new HttpCallbackListener() {
                                public void callback(String result) {
                                    Uri iUri;
                                    long baseTime = -1;
                                    if (result == null) {
                                        try {
                                            ActivityInfoDAO.restoreReferralTrackingInfo(context3, arrayList2);
                                            IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, responseResult null Error", 3, false);
                                        } catch (Exception e) {
                                            ActivityInfoDAO.restoreReferralTrackingInfo(context3, arrayList2);
                                            if (e != null) {
                                                e.printStackTrace();
                                                IgawLogger.Logging(context3, IgawConstant.QA_TAG, e.toString(), 0);
                                            }
                                        } finally {
                                            CommonHttpManager.this.setOnReferrerCall(false);
                                        }
                                    } else {
                                        AppImpressionDAO.setSynAdbrix(context3);
                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, getReferral response String : " + result, 3, false);
                                        RequestParameter atParam = RequestParameter.getATRequestParameter(context3);
                                        JSONObject jSONObject = new JSONObject(result);
                                        try {
                                            if (jSONObject.has(HttpManager.SERVER_BASE_TIME)) {
                                                baseTime = jSONObject.getLong(HttpManager.SERVER_BASE_TIME);
                                                AppImpressionDAO.setServerBaseTimeOffset(context3, baseTime - System.currentTimeMillis());
                                            }
                                        } catch (Exception e2) {
                                            e2.printStackTrace();
                                        }
                                        String deeplink = "";
                                        if (jSONObject.getBoolean(HttpManager.RESULT)) {
                                            if (!jSONObject.isNull(HttpManager.DATA)) {
                                                JSONObject jSONObject2 = new JSONObject(jSONObject.getString(HttpManager.DATA));
                                                JSONObject conversionHistory = null;
                                                if (jSONObject2.has(HttpManager.CONVERSION_HISTORY) && !jSONObject2.isNull(HttpManager.CONVERSION_HISTORY)) {
                                                    conversionHistory = new JSONObject(jSONObject2.getString(HttpManager.CONVERSION_HISTORY));
                                                }
                                                JSONArray jSONArray = new JSONArray(jSONObject2.getString(HttpManager.CONVERSION_KEY_LIST));
                                                for (int i = 0; i < jSONArray.length(); i++) {
                                                    int key = jSONArray.getInt(i);
                                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > key : " + key, 3, false);
                                                    if (key != -1 && !atParam.getConversionCache().contains(Integer.valueOf(key))) {
                                                        long completeTime = -1;
                                                        if (conversionHistory != null) {
                                                            if (conversionHistory.has(new StringBuilder(String.valueOf(key)).toString())) {
                                                                completeTime = conversionHistory.getLong(new StringBuilder(String.valueOf(key)).toString());
                                                            }
                                                        }
                                                        atParam.setConversionCache(key);
                                                        atParam.setConversionCacheHistory(key, completeTime);
                                                    }
                                                }
                                                long referralKey = jSONObject2.getLong(HttpManager.REFERRALKEY);
                                                if (jSONObject2.has(HttpManager.DEEPLINK)) {
                                                    deeplink = jSONObject2.getString(HttpManager.DEEPLINK);
                                                    try {
                                                        iUri = Uri.parse("http://igaworks.com" + deeplink.substring(deeplink.indexOf(63), deeplink.length()));
                                                    } catch (Exception e3) {
                                                        iUri = null;
                                                    }
                                                    if (iUri != null) {
                                                        try {
                                                            int conversionKey = Integer.parseInt(iUri.getQueryParameter("ck"));
                                                            if (atParam.getProcessedConversions().contains(Integer.valueOf(conversionKey))) {
                                                                Log.d(IgawConstant.QA_TAG, "Deferrer Link: " + deeplink);
                                                                deeplink = "";
                                                            } else {
                                                                atParam.setProcessedConversions(conversionKey);
                                                            }
                                                        } catch (Exception e4) {
                                                        }
                                                    }
                                                }
                                                Log.d(IgawConstant.QA_TAG, "fetchDeferredLinkData >> referralKey = " + referralKey + " Deeplink: " + deeplink);
                                                int channelType = -1;
                                                if (jSONObject2.has("channel_type") && !jSONObject2.isNull("channel_type")) {
                                                    channelType = jSONObject2.getInt("channel_type");
                                                }
                                                IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > referralKey : " + referralKey, 3, false);
                                                if (referralKey != -1) {
                                                    atParam.setADBrixUserInfo_ReferralKey(referralKey);
                                                }
                                                if (jSONObject2.has(HttpManager.SUBREFERRALKEY)) {
                                                    String subreferralKey = jSONObject2.getString(HttpManager.SUBREFERRALKEY);
                                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > subreferralKey : " + subreferralKey, 3, false);
                                                    atParam.setADBrixUserInfo_SubReferralKey(subreferralKey);
                                                }
                                                try {
                                                    if (jSONObject2.has(HttpManager.POSTBACK_REFERRER_DATA)) {
                                                        String referral_data = jSONObject2.getString(HttpManager.POSTBACK_REFERRER_DATA);
                                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > POSTBACK_REFERRER_DATA : " + referral_data, 3, false);
                                                        atParam.setADBrixUserInfo_referral_data(referral_data);
                                                    }
                                                    if (jSONObject2.has(HttpManager.POSTBACK_ENGAGEMENT_DATETIME) && !jSONObject2.isNull(HttpManager.POSTBACK_ENGAGEMENT_DATETIME)) {
                                                        String reEngDatetime = jSONObject2.getString(HttpManager.POSTBACK_ENGAGEMENT_DATETIME);
                                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > reengagement_datetime : " + reEngDatetime, 3, false);
                                                        atParam.setADBrixUserInfo_reengagment_datetime(reEngDatetime);
                                                    }
                                                    if (jSONObject2.has(HttpManager.REENGAGEMENT_CONVERSION_KEY)) {
                                                        long reengagement_conversion_key = jSONObject2.getLong(HttpManager.REENGAGEMENT_CONVERSION_KEY);
                                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > REENGAGEMENT_CONVERSION_KEY : " + reengagement_conversion_key, 3, false);
                                                        atParam.setADBrixUserInfo_reengagement_conversion_key(reengagement_conversion_key);
                                                    }
                                                } catch (Exception e5) {
                                                    Log.e(IgawConstant.QA_TAG, "POSTBACK_REFERRER_DATA error: " + e5.getMessage());
                                                }
                                                try {
                                                    if (jSONObject2.has(HttpManager.POSTBACK_REENGAGEMENT_DATA)) {
                                                        String reengagement_data = jSONObject2.getString(HttpManager.POSTBACK_REENGAGEMENT_DATA);
                                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > POSTBACK_REENGAGEMENT_DATA : " + reengagement_data, 3, false);
                                                        atParam.setADBrixUserInfo_reengagement_data(reengagement_data);
                                                    }
                                                } catch (Exception e6) {
                                                    Log.e(IgawConstant.QA_TAG, "POSTBACK_REENGAGEMENT_DATA error: " + e6.getMessage());
                                                }
                                                try {
                                                    if (jSONObject2.has(HttpManager.LAST_REFERRAL_DATA)) {
                                                        String last_referral_data = jSONObject2.getString(HttpManager.LAST_REFERRAL_DATA);
                                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > LAST_REFERRAL_DATA : " + last_referral_data, 3, false);
                                                        atParam.setADBrixUserInfo_last_referral_data(last_referral_data);
                                                    }
                                                    if (jSONObject2.has(HttpManager.LAST_REFERRAL_DATETIME)) {
                                                        String last_referral_datetime = jSONObject2.getString(HttpManager.LAST_REFERRAL_DATETIME);
                                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > LAST_REFERRAL_DATETIME : " + last_referral_datetime, 3, false);
                                                        atParam.setADBrixUserInfo_last_referral_datetime(last_referral_datetime);
                                                    }
                                                    if (jSONObject2.has(HttpManager.LAST_REFERRAL_KEY)) {
                                                        long last_referral_key = jSONObject2.getLong(HttpManager.LAST_REFERRAL_KEY);
                                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > LAST_REFERRAL_KEY : " + last_referral_key, 3, false);
                                                        atParam.setADBrixUserInfo_last_referral_key(last_referral_key);
                                                    }
                                                } catch (Exception e7) {
                                                    Log.e(IgawConstant.QA_TAG, "LAST_REFERRAL_DATA error: " + e7.getMessage());
                                                }
                                                if (jSONObject2.has(HttpManager.REF_USN) && !jSONObject2.isNull(HttpManager.REF_USN)) {
                                                    String refUsn = jSONObject2.getString(HttpManager.REF_USN);
                                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > refusn : " + refUsn, 3, false);
                                                    atParam.setADBrixUserInfo_Refusn(refUsn);
                                                }
                                                if (jSONObject2.has(HttpManager.SHARD_NO) && !jSONObject2.isNull(HttpManager.SHARD_NO)) {
                                                    int shardNo = jSONObject2.getInt(HttpManager.SHARD_NO);
                                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > shard_no : " + shardNo, 3, false);
                                                    atParam.setADBrixUserInfo_ShardNo(shardNo);
                                                }
                                                if (jSONObject2.has(HttpManager.INSTALL_DATETIME) && !jSONObject2.isNull(HttpManager.INSTALL_DATETIME)) {
                                                    String installDatetime = jSONObject2.getString(HttpManager.INSTALL_DATETIME);
                                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > install_datetime : " + installDatetime, 3, false);
                                                    requestParameter2.setNewInstall(CommonHttpManager.this.isNewInstall(context3, baseTime, installDatetime));
                                                    atParam.setADBrixUserInfo_install_datetime(installDatetime);
                                                }
                                                if (channelType != -1) {
                                                    atParam.setChannelType(channelType);
                                                }
                                                long adbrix_user_no = jSONObject2.getLong(HttpManager.ADBRIX_USER_NO);
                                                IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > adbrix_user_no : " + adbrix_user_no, 3, false);
                                                atParam.setADBrixUserInfo(adbrix_user_no, System.currentTimeMillis());
                                            }
                                            if (CommonFrameworkImpl.getActivityListener() != null) {
                                                for (CommonActivityListener item : CommonFrameworkImpl.getActivityListener()) {
                                                    item.onGetReferralResponse(context3, result);
                                                }
                                            }
                                            if (CommonFrameworkImpl.httpManager == null) {
                                                CommonFrameworkImpl.httpManager = new CommonHttpManager();
                                            }
                                            InternalAction.getInstance().trackingForAdbrixCall(context3, CommonFrameworkImpl.isTest, CommonFrameworkImpl.httpManager, "n/a", "n/a", 0);
                                            if (deeplink != null && !deeplink.equals("") && !deeplink.equals("null") && !CommonHttpManager.isReturnDL && AppImpressionDAO.getDeferrerlink(context3).equals("")) {
                                                CommonHttpManager.isReturnDL = true;
                                                AppImpressionDAO.setDeferrerlink(context3, deeplink);
                                                if (CommonHttpManager.mDeferredLinkListener != null) {
                                                    CommonHttpManager.mDeferredLinkListener.onReceiveDeeplink(deeplink);
                                                    CommonHttpManager.mDeferredLinkListener = null;
                                                } else {
                                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "mDeferredLinkListener is not null", 2, false);
                                                }
                                            }
                                        } else {
                                            ActivityInfoDAO.restoreReferralTrackingInfo(context3, arrayList2);
                                            IgawLogger.Logging(context3, IgawConstant.QA_TAG, "callbackReferrerADBrix result false", 0, false);
                                        }
                                        CommonHttpManager.this.setOnReferrerCall(false);
                                    }
                                }
                            }, false, true));
                            ((Thread) threadW.get()).setDaemon(true);
                            ((Thread) threadW.get()).start();
                            return;
                        }
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixTracer > referrerCallForADBrix() : referral call info already saved.", 3, false);
                        CommonHttpManager.this.setOnReferrerCall(false);
                    } catch (Exception e) {
                        e.printStackTrace();
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, e.getMessage(), 0);
                        CommonHttpManager.this.setOnReferrerCall(false);
                        ActivityInfoDAO.restoreReferralTrackingInfo(context, activity_info_list);
                    }
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
            IgawLogger.Logging(context, IgawConstant.QA_TAG, e.getMessage(), 0);
            setOnReferrerCall(false);
            ActivityInfoDAO.restoreReferralTrackingInfo(context, activity_info_list);
        }
    }

    public void CPI_referrerCallForADBrix(final RequestParameter parameter, final Context context, final ArrayList<String> activity_info_list) {
        setOnReferrerCall(true);
        if (getOnCPIReferrerCall()) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "CPI referrerCallForADBrix > referral call already sent.", 3);
            return;
        }
        setOnCPIReferrerCall(true);
        try {
            DeviceIDManger.getInstance(context).getAndroidADID(context, new ADIDCallbackListener() {
                public void onResult(AdInfo adInfo) {
                    boolean isLimitAdTrackingEnabled;
                    String url = CommonHttpManager.this.REFERRER_REQUEST_URL_FOR_ADBrix;
                    try {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "CPI referrerCallForADBrix", 3, false);
                        RequestParameter requestParameter = parameter;
                        Context context = context;
                        ArrayList arrayList = activity_info_list;
                        String id = adInfo == null ? "" : adInfo.getId();
                        if (adInfo == null) {
                            isLimitAdTrackingEnabled = false;
                        } else {
                            isLimitAdTrackingEnabled = adInfo.isLimitAdTrackingEnabled();
                        }
                        String param = AESGetTrackParam.encrypt_hashkey(requestParameter.getReferrerTrackingParameter(context, arrayList, null, id, isLimitAdTrackingEnabled), parameter.getHashkey());
                        boolean isAdbrixSyn = AppImpressionDAO.getSynAdbrix(CommonFrameworkImpl.getContext());
                        if (parameter.getReferralKey() < 1 || !isAdbrixSyn) {
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "CPI referrerCallForADBrix > referral call send.", 3, false);
                            HashMap<String, String> paramValuePair = new HashMap<>();
                            paramValuePair.put("k", new StringBuilder(String.valueOf(parameter.getAppkey())).toString());
                            paramValuePair.put("j", param);
                            Context context2 = context;
                            final Context context3 = context;
                            final ArrayList arrayList2 = activity_info_list;
                            WeakReference<Thread> threadW = new WeakReference<>(new HttpsUrlConnectionThread(context2, 1, url, paramValuePair, new HttpCallbackListener() {
                                public void callback(String result) {
                                    Uri iUri;
                                    if (result == null) {
                                        try {
                                            ActivityInfoDAO.restoreReferralTrackingInfo(context3, arrayList2);
                                            IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, responseResult null Error", 3, false);
                                        } catch (Exception e) {
                                            ActivityInfoDAO.restoreReferralTrackingInfo(context3, arrayList2);
                                            if (e != null) {
                                                e.printStackTrace();
                                                IgawLogger.Logging(context3, IgawConstant.QA_TAG, e.toString(), 0);
                                            }
                                        } finally {
                                            CommonHttpManager.this.setOnReferrerCall(false);
                                            CommonHttpManager.this.setOnCPIReferrerCall(false);
                                        }
                                    } else {
                                        AppImpressionDAO.setSynAdbrix(context3);
                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, getReferral response String : " + result, 3, false);
                                        RequestParameter atParam = RequestParameter.getATRequestParameter(context3);
                                        JSONObject jSONObject = new JSONObject(result);
                                        try {
                                            if (jSONObject.has(HttpManager.SERVER_BASE_TIME)) {
                                                AppImpressionDAO.setServerBaseTimeOffset(context3, jSONObject.getLong(HttpManager.SERVER_BASE_TIME) - System.currentTimeMillis());
                                            }
                                        } catch (Exception e2) {
                                            e2.printStackTrace();
                                        }
                                        String deeplink = "";
                                        if (jSONObject.getBoolean(HttpManager.RESULT)) {
                                            if (!jSONObject.isNull(HttpManager.DATA)) {
                                                JSONObject jSONObject2 = new JSONObject(jSONObject.getString(HttpManager.DATA));
                                                JSONObject conversionHistory = null;
                                                if (jSONObject2.has(HttpManager.CONVERSION_HISTORY) && !jSONObject2.isNull(HttpManager.CONVERSION_HISTORY)) {
                                                    conversionHistory = new JSONObject(jSONObject2.getString(HttpManager.CONVERSION_HISTORY));
                                                }
                                                JSONArray jSONArray = new JSONArray(jSONObject2.getString(HttpManager.CONVERSION_KEY_LIST));
                                                for (int i = 0; i < jSONArray.length(); i++) {
                                                    int key = jSONArray.getInt(i);
                                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > key : " + key, 3, false);
                                                    if (key != -1 && !atParam.getConversionCache().contains(Integer.valueOf(key))) {
                                                        long completeTime = -1;
                                                        if (conversionHistory != null) {
                                                            if (conversionHistory.has(new StringBuilder(String.valueOf(key)).toString())) {
                                                                completeTime = conversionHistory.getLong(new StringBuilder(String.valueOf(key)).toString());
                                                            }
                                                        }
                                                        atParam.setConversionCache(key);
                                                        atParam.setConversionCacheHistory(key, completeTime);
                                                    }
                                                }
                                                long referralKey = jSONObject2.getLong(HttpManager.REFERRALKEY);
                                                if (jSONObject2.has(HttpManager.DEEPLINK)) {
                                                    deeplink = jSONObject2.getString(HttpManager.DEEPLINK);
                                                    try {
                                                        iUri = Uri.parse("http://igaworks.com" + deeplink.substring(deeplink.indexOf(63), deeplink.length()));
                                                    } catch (Exception e3) {
                                                        iUri = null;
                                                    }
                                                    if (iUri != null) {
                                                        try {
                                                            int conversionKey = Integer.parseInt(iUri.getQueryParameter("ck"));
                                                            if (atParam.getProcessedConversions().contains(Integer.valueOf(conversionKey))) {
                                                                Log.d(IgawConstant.QA_TAG, "Deferrer Link: " + deeplink);
                                                                deeplink = "";
                                                            } else {
                                                                atParam.setProcessedConversions(conversionKey);
                                                            }
                                                        } catch (Exception e4) {
                                                        }
                                                    }
                                                }
                                                Log.d(IgawConstant.QA_TAG, "fetchDeferredLinkData >> referralKey = " + referralKey + " Deeplink: " + deeplink);
                                                int channelType = -1;
                                                if (jSONObject2.has("channel_type") && !jSONObject2.isNull("channel_type")) {
                                                    channelType = jSONObject2.getInt("channel_type");
                                                }
                                                IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > referralKey : " + referralKey, 3, false);
                                                if (referralKey != -1) {
                                                    atParam.setADBrixUserInfo_ReferralKey(referralKey);
                                                }
                                                if (jSONObject2.has(HttpManager.SUBREFERRALKEY)) {
                                                    String subreferralKey = jSONObject2.getString(HttpManager.SUBREFERRALKEY);
                                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > subreferralKey : " + subreferralKey, 3, false);
                                                    atParam.setADBrixUserInfo_SubReferralKey(subreferralKey);
                                                }
                                                try {
                                                    if (jSONObject2.has(HttpManager.POSTBACK_REFERRER_DATA)) {
                                                        String referral_data = jSONObject2.getString(HttpManager.POSTBACK_REFERRER_DATA);
                                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > referral_data : " + referral_data, 3, false);
                                                        atParam.setADBrixUserInfo_referral_data(referral_data);
                                                    }
                                                    if (jSONObject2.has(HttpManager.POSTBACK_ENGAGEMENT_DATETIME) && !jSONObject2.isNull(HttpManager.POSTBACK_ENGAGEMENT_DATETIME)) {
                                                        String reEngDatetime = jSONObject2.getString(HttpManager.POSTBACK_ENGAGEMENT_DATETIME);
                                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > reengagement_datetime : " + reEngDatetime, 3, false);
                                                        atParam.setADBrixUserInfo_reengagment_datetime(reEngDatetime);
                                                    }
                                                    if (jSONObject2.has(HttpManager.REENGAGEMENT_CONVERSION_KEY)) {
                                                        long reengagement_conversion_key = jSONObject2.getLong(HttpManager.REENGAGEMENT_CONVERSION_KEY);
                                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > REENGAGEMENT_CONVERSION_KEY : " + reengagement_conversion_key, 3, false);
                                                        atParam.setADBrixUserInfo_reengagement_conversion_key(reengagement_conversion_key);
                                                    }
                                                } catch (Exception e5) {
                                                    Log.e(IgawConstant.QA_TAG, "POSTBACK_REFERRER_DATA error: " + e5.getMessage());
                                                }
                                                try {
                                                    if (jSONObject2.has(HttpManager.POSTBACK_REENGAGEMENT_DATA)) {
                                                        String reengagement_data = jSONObject2.getString(HttpManager.POSTBACK_REENGAGEMENT_DATA);
                                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > POSTBACK_REENGAGEMENT_DATA : " + reengagement_data, 3, false);
                                                        atParam.setADBrixUserInfo_reengagement_data(reengagement_data);
                                                    }
                                                } catch (Exception e6) {
                                                    Log.e(IgawConstant.QA_TAG, "POSTBACK_REENGAGEMENT_DATA error: " + e6.getMessage());
                                                }
                                                try {
                                                    if (jSONObject2.has(HttpManager.LAST_REFERRAL_DATA)) {
                                                        String last_referral_data = jSONObject2.getString(HttpManager.LAST_REFERRAL_DATA);
                                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > LAST_REFERRAL_DATA : " + last_referral_data, 3, false);
                                                        atParam.setADBrixUserInfo_last_referral_data(last_referral_data);
                                                    }
                                                    if (jSONObject2.has(HttpManager.LAST_REFERRAL_DATETIME)) {
                                                        String last_referral_datetime = jSONObject2.getString(HttpManager.LAST_REFERRAL_DATETIME);
                                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > LAST_REFERRAL_DATETIME : " + last_referral_datetime, 3, false);
                                                        atParam.setADBrixUserInfo_last_referral_datetime(last_referral_datetime);
                                                    }
                                                    if (jSONObject2.has(HttpManager.LAST_REFERRAL_KEY)) {
                                                        long last_referral_key = jSONObject2.getLong(HttpManager.LAST_REFERRAL_KEY);
                                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > LAST_REFERRAL_KEY : " + last_referral_key, 3, false);
                                                        atParam.setADBrixUserInfo_last_referral_key(last_referral_key);
                                                    }
                                                } catch (Exception e7) {
                                                    Log.e(IgawConstant.QA_TAG, "LAST_REFERRAL_DATA error: " + e7.getMessage());
                                                }
                                                if (jSONObject2.has(HttpManager.REF_USN) && !jSONObject2.isNull(HttpManager.REF_USN)) {
                                                    String refUsn = jSONObject2.getString(HttpManager.REF_USN);
                                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > refusn : " + refUsn, 3, false);
                                                    atParam.setADBrixUserInfo_Refusn(refUsn);
                                                }
                                                if (jSONObject2.has(HttpManager.SHARD_NO) && !jSONObject2.isNull(HttpManager.SHARD_NO)) {
                                                    int shardNo = jSONObject2.getInt(HttpManager.SHARD_NO);
                                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > shard_no : " + shardNo, 3, false);
                                                    atParam.setADBrixUserInfo_ShardNo(shardNo);
                                                }
                                                if (jSONObject2.has(HttpManager.INSTALL_DATETIME) && !jSONObject2.isNull(HttpManager.INSTALL_DATETIME)) {
                                                    String installDatetime = jSONObject2.getString(HttpManager.INSTALL_DATETIME);
                                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > install_datetime : " + installDatetime, 3, false);
                                                    atParam.setADBrixUserInfo_install_datetime(installDatetime);
                                                }
                                                if (channelType != -1) {
                                                    atParam.setChannelType(channelType);
                                                }
                                                long adbrix_user_no = jSONObject2.getLong(HttpManager.ADBRIX_USER_NO);
                                                IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > adbrix_user_no : " + adbrix_user_no, 3, false);
                                                atParam.setADBrixUserInfo(adbrix_user_no, System.currentTimeMillis());
                                            }
                                            ReferralInfoDAO.clearOnReceiveReferralFlag(context3);
                                            if (CommonFrameworkImpl.getActivityListener() != null) {
                                                for (CommonActivityListener item : CommonFrameworkImpl.getActivityListener()) {
                                                    item.onGetReferralResponse(context3, result);
                                                }
                                            }
                                            if (CommonFrameworkImpl.httpManager == null) {
                                                CommonFrameworkImpl.httpManager = new CommonHttpManager();
                                            }
                                            InternalAction.getInstance().trackingForAdbrixCall(context3, CommonFrameworkImpl.isTest, CommonFrameworkImpl.httpManager, "n/a", "n/a", 0);
                                            if (deeplink != null && !deeplink.equals("") && !deeplink.equals("null") && !CommonHttpManager.isReturnDL && AppImpressionDAO.getDeferrerlink(context3).equals("")) {
                                                CommonHttpManager.isReturnDL = true;
                                                AppImpressionDAO.setDeferrerlink(context3, deeplink);
                                                if (CommonHttpManager.mDeferredLinkListener != null) {
                                                    CommonHttpManager.mDeferredLinkListener.onReceiveDeeplink(deeplink);
                                                    CommonHttpManager.mDeferredLinkListener = null;
                                                } else {
                                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "mDeferredLinkListener is not null", 2, false);
                                                }
                                            }
                                        } else {
                                            ActivityInfoDAO.restoreReferralTrackingInfo(context3, arrayList2);
                                            IgawLogger.Logging(context3, IgawConstant.QA_TAG, "callbackReferrerADBrix result false", 0, false);
                                        }
                                        CommonHttpManager.this.setOnReferrerCall(false);
                                        CommonHttpManager.this.setOnCPIReferrerCall(false);
                                    }
                                }
                            }, false, true));
                            ((Thread) threadW.get()).setDaemon(true);
                            ((Thread) threadW.get()).start();
                            return;
                        }
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixTracer > referrerCallForADBrix() : referral call info already saved.", 3, false);
                        CommonHttpManager.this.setOnReferrerCall(false);
                        CommonHttpManager.this.setOnCPIReferrerCall(false);
                    } catch (Exception e) {
                        e.printStackTrace();
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, e.getMessage(), 0);
                        CommonHttpManager.this.setOnReferrerCall(false);
                        CommonHttpManager.this.setOnCPIReferrerCall(false);
                        ActivityInfoDAO.restoreReferralTrackingInfo(context, activity_info_list);
                    }
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
            IgawLogger.Logging(context, IgawConstant.QA_TAG, e.getMessage(), 0);
            setOnReferrerCall(false);
            setOnCPIReferrerCall(false);
            ActivityInfoDAO.restoreReferralTrackingInfo(context, activity_info_list);
        }
    }

    public void trackingForADBrix(RequestParameter parameter, Context context, ArrayList<TrackingActivityModel> activity_info_list, ArrayList<TrackingActivityModel> imp_info_list) {
        try {
            final Context context2 = context;
            final ArrayList<TrackingActivityModel> arrayList = activity_info_list;
            final ArrayList<TrackingActivityModel> arrayList2 = imp_info_list;
            final RequestParameter requestParameter = parameter;
            DeviceIDManger.getInstance(context).getAndroidADID(context, new ADIDCallbackListener() {
                public void onResult(AdInfo adInfo) {
                    boolean isLimitAdTrackingEnabled;
                    String url = CommonHttpManager.this.TRACKING_REQUEST_URL_FOR_ADBrix;
                    try {
                        IgawLogger.Logging(context2, IgawConstant.QA_TAG, "trackingForADBrix", 3);
                        ArrayList<String> str_activity_info_list = new ArrayList<>();
                        ArrayList<String> str_imp_info_list = new ArrayList<>();
                        for (int x = 0; x < arrayList.size(); x++) {
                            str_activity_info_list.add(((TrackingActivityModel) arrayList.get(x)).getValue());
                        }
                        for (int y = 0; y < arrayList2.size(); y++) {
                            str_imp_info_list.add(((TrackingActivityModel) arrayList2.get(y)).getValue());
                        }
                        RequestParameter requestParameter = requestParameter;
                        Context context = context2;
                        String id = adInfo == null ? "" : adInfo.getId();
                        if (adInfo == null) {
                            isLimitAdTrackingEnabled = false;
                        } else {
                            isLimitAdTrackingEnabled = adInfo.isLimitAdTrackingEnabled();
                        }
                        String param = AESGetTrackParam.encrypt(requestParameter.getTrackingParameterForADBrix(context, str_activity_info_list, str_imp_info_list, id, isLimitAdTrackingEnabled), requestParameter.getHashkey());
                        HashMap<String, String> paramValuePair = new HashMap<>();
                        paramValuePair.put("k", new StringBuilder(String.valueOf(requestParameter.getAppkey())).toString());
                        paramValuePair.put("j", param);
                        Context context2 = context2;
                        final Context context3 = context2;
                        final ArrayList arrayList = arrayList;
                        final ArrayList arrayList2 = arrayList2;
                        WeakReference<Thread> threadW = new WeakReference<>(new HttpsUrlConnectionThread(context2, 1, url, paramValuePair, new HttpCallbackListener() {
                            public void callback(String result) {
                                if (result != null) {
                                    try {
                                        if (!result.equals("")) {
                                            IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, tracking response result : " + result, 3, false);
                                            JSONObject jsonObject = new JSONObject(result);
                                            try {
                                                if (jsonObject.has(HttpManager.SERVER_BASE_TIME)) {
                                                    AppImpressionDAO.setServerBaseTimeOffset(context3, jsonObject.getLong(HttpManager.SERVER_BASE_TIME) - System.currentTimeMillis());
                                                }
                                            } catch (Exception e) {
                                                e.printStackTrace();
                                            }
                                            if (!jsonObject.getBoolean(HttpManager.RESULT)) {
                                                CommonHttpManager.this.restoreTrackingInfo_Common(context3, arrayList, arrayList2);
                                                IgawLogger.Logging(context3, IgawConstant.QA_TAG, "responseResult Result = false", 2, false);
                                                return;
                                            }
                                            TrackingActivitySQLiteDB.getInstance(context3).removeTrackingActivities(arrayList, context3, TrackingActivitySQLiteOpenHelper.TABLE_APP_TRACKING);
                                            TrackingActivitySQLiteDB.getInstance(context3).removeTrackingActivities(arrayList2, context3, TrackingActivitySQLiteOpenHelper.TABLE_IMPRESSION_TRACKING);
                                            return;
                                        }
                                    } catch (Exception e2) {
                                        e2.printStackTrace();
                                        StackTraceElement[] stackTrace = new Throwable().getStackTrace();
                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, e2.getMessage(), 0);
                                        CommonHttpManager.this.restoreTrackingInfo_Common(context3, arrayList, arrayList2);
                                        return;
                                    }
                                }
                                CommonHttpManager.this.restoreTrackingInfo_Common(context3, arrayList, arrayList2);
                                IgawLogger.Logging(context3, IgawConstant.QA_TAG, "responseResult null Error", 0, false);
                            }
                        }, false, false));
                        ((Thread) threadW.get()).setDaemon(true);
                        ((Thread) threadW.get()).start();
                    } catch (SocketTimeoutException e) {
                        e.printStackTrace();
                        IgawLogger.Logging(context2, IgawConstant.QA_TAG, e.toString(), 0);
                        CommonHttpManager.this.restoreTrackingInfo_Common(context2, arrayList, arrayList2);
                    } catch (Exception e2) {
                        if (!(arrayList == null || arrayList.size() == 0)) {
                            CommonHttpManager.this.restoreTrackingInfo_Common(context2, arrayList, arrayList2);
                        }
                        e2.printStackTrace();
                        IgawLogger.Logging(context2, IgawConstant.QA_TAG, e2.toString(), 0);
                    }
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
            IgawLogger.Logging(context, IgawConstant.QA_TAG, e.toString(), 0);
            restoreTrackingInfo_Common(context, activity_info_list, imp_info_list);
        }
    }

    /* access modifiers changed from: protected */
    public void restoreTrackingInfo_Common(Context context, ArrayList<TrackingActivityModel> activity_info_list, ArrayList<TrackingActivityModel> imp_info_list) {
        TrackingActivitySQLiteDB.getInstance(context).reclaimDirtyDataForRetry(activity_info_list, context, TrackingActivitySQLiteOpenHelper.TABLE_APP_TRACKING);
        TrackingActivitySQLiteDB.getInstance(context).reclaimDirtyDataForRetry(imp_info_list, context, TrackingActivitySQLiteOpenHelper.TABLE_IMPRESSION_TRACKING);
    }

    public void demographicCallForADBrix(RequestParameter parameter, final Context context) {
        String url = this.DEMOGRAPHIC_REQUEST_URL_FOR_ADBrix;
        try {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "demoCallForADBrix", 3, false);
            String param = AESGetTrackParam.encrypt(parameter.getDemographicParameter(), parameter.getHashkey());
            HashMap<String, String> paramValuePair = new HashMap<>();
            paramValuePair.put("k", new StringBuilder(String.valueOf(parameter.getAppkey())).toString());
            paramValuePair.put("j", param);
            WeakReference<Thread> threadW = new WeakReference<>(new HttpsUrlConnectionThread(context, 1, url, paramValuePair, new HttpCallbackListener() {
                public void callback(String result) {
                    if (result == null) {
                        try {
                            throw new Exception("responseResult null Error");
                        } catch (Exception e) {
                            e.printStackTrace();
                            StackTraceElement[] stackTrace = new Throwable().getStackTrace();
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, e.getMessage(), 0);
                        }
                    } else if (new JSONObject(result).getBoolean(HttpManager.RESULT)) {
                        SharedPreferences trackingPref = context.getSharedPreferences("demoForTracking", 0);
                        Editor trackingEditor = trackingPref.edit();
                        for (Entry<String, ?> entry : trackingPref.getAll().entrySet()) {
                            String key = entry.getKey();
                            LocalDemograhpicDAO.getInstance(context).save_demographic_local(key, (String) entry.getValue());
                            trackingEditor.remove(key);
                        }
                        trackingEditor.apply();
                    } else {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "callbackDemographicADBrix false", 3, false);
                    }
                }
            }, false, false));
            ((Thread) threadW.get()).setDaemon(true);
            ((Thread) threadW.get()).start();
        } catch (Exception e) {
            e.printStackTrace();
            StackTraceElement[] stackTrace = new Throwable().getStackTrace();
            IgawLogger.Logging(context, IgawConstant.QA_TAG, e.getMessage(), 0);
        }
    }

    public void conversionForDeeplink(RequestParameter parameter, final Context context, final ArrayList<DeeplinkConversionItem> conversions) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "conversionForDeeplink", 2, false);
                    DeviceIDManger instance = DeviceIDManger.getInstance(context);
                    Context context = context;
                    final ArrayList arrayList = conversions;
                    final Context context2 = context;
                    instance.getAndroidADID(context, new ADIDCallbackListener() {
                        public void onResult(AdInfo adInfo) {
                            String url = CommonHttpManager.this.DEEP_LINK_CONVERSION_FOR_ADBrix;
                            JSONArray arr = new JSONArray();
                            Iterator it = arrayList.iterator();
                            while (it.hasNext()) {
                                DeeplinkConversionItem item = (DeeplinkConversionItem) it.next();
                                try {
                                    JSONObject obj = new JSONObject();
                                    obj.put("clickId", item.getCommerceClickID());
                                    obj.put("adid", adInfo.getId());
                                    obj.put("mtime", new Date().getTime());
                                    arr.put(obj);
                                } catch (JSONException e) {
                                    e.printStackTrace();
                                }
                            }
                            try {
                                IgawLogger.Logging(context2, IgawConstant.QA_TAG, "conversionForDeeplink param : " + arr.toString(), 2);
                                Context context = context2;
                                String jSONArray = arr.toString();
                                final Context context2 = context2;
                                final ArrayList arrayList = arrayList;
                                WeakReference<Thread> threadW = new WeakReference<>(new JsonHttpsUrlConnectionThread(context, 1, url, jSONArray, new HttpCallbackListener() {
                                    public void callback(String result) {
                                        if (result != null) {
                                            try {
                                                if (!result.equals("")) {
                                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, "ADBrixTracer, deeplink conversion response result : " + result, 2, false);
                                                    JSONObject jsonObject = new JSONObject(result);
                                                    if (!jsonObject.has("errMsg") || !jsonObject.isNull("errMsg")) {
                                                        CommonHttpManager.this.restoreConversionInfo(context2, arrayList);
                                                        return;
                                                    }
                                                    Task forResult = Task.forResult(null);
                                                    final Context context = context2;
                                                    final ArrayList arrayList = arrayList;
                                                    forResult.continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Object, Void>() {
                                                        public Void then(Task<Object> task) throws Exception {
                                                            DeeplinkConversionRetryDAO.getDAO(context).removeDeeplinkConversionItems(arrayList, context);
                                                            return null;
                                                        }
                                                    }, (Executor) Task.BACKGROUND_EXECUTOR);
                                                    return;
                                                }
                                            } catch (Exception e) {
                                                e.printStackTrace();
                                                CommonHttpManager.this.restoreConversionInfo(context2, arrayList);
                                                StackTraceElement[] stackTrace = new Throwable().getStackTrace();
                                                IgawLogger.Logging(context2, IgawConstant.QA_TAG, e.getMessage(), 0);
                                                return;
                                            }
                                        }
                                        CommonHttpManager.this.restoreConversionInfo(context2, arrayList);
                                        Log.e(IgawConstant.QA_TAG, "responseResult null Error");
                                    }
                                }, false, false));
                                ((Thread) threadW.get()).setDaemon(true);
                                ((Thread) threadW.get()).start();
                            } catch (Exception e2) {
                                CommonHttpManager.this.restoreConversionInfo(context2, arrayList);
                                e2.printStackTrace();
                                IgawLogger.Logging(context2, IgawConstant.QA_TAG, e2.toString(), 0);
                            }
                        }
                    });
                } catch (Exception e) {
                    e.printStackTrace();
                    CommonHttpManager.this.restoreConversionInfo(context, conversions);
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, e.toString(), 0);
                }
            }
        }).start();
    }

    public void restoreConversionInfo(final Context context, final List<DeeplinkConversionItem> items) {
        Task.forResult(null).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Object, Void>() {
            public Void then(Task<Object> task) throws Exception {
                DeeplinkConversionRetryDAO dao = DeeplinkConversionRetryDAO.getDAO(context);
                for (DeeplinkConversionItem item : items) {
                    if (item.getRetryCnt() > 5) {
                        dao.removeRetryCount(item.getKey());
                    } else {
                        dao.updateOrInsertConversionForRetry(item.getKey(), item.getConversionKey(), item.getCommerceClickID());
                    }
                }
                return null;
            }
        }, (Executor) Task.BACKGROUND_EXECUTOR);
    }

    /* access modifiers changed from: protected */
    public synchronized void setOnReferrerCall(boolean _onReferrerCall) {
        onReferrerCall = _onReferrerCall;
    }

    /* access modifiers changed from: protected */
    public synchronized boolean getOnReferrerCall() {
        return onReferrerCall;
    }

    /* access modifiers changed from: protected */
    public synchronized void setOnCPIReferrerCall(boolean _onReferrerCall) {
        onCPIReferrerCall = _onReferrerCall;
    }

    /* access modifiers changed from: protected */
    public synchronized boolean getOnCPIReferrerCall() {
        return onCPIReferrerCall;
    }

    public void setDeferredLinkListener(Context context, DeferredLinkListener _listener) {
        IgawLogger.Logging(context, IgawConstant.QA_TAG, "set DeferredLink Listener", 2, true);
        mDeferredLinkListener = _listener;
    }

    /* access modifiers changed from: private */
    public boolean isNewInstall(Context context, long servertime_utc, String installDateTime_kst) {
        if (servertime_utc == -1) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "checking new install : missing baseTime", 3, false);
            return true;
        }
        SimpleDateFormat sdf = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT, Locale.KOREA);
        sdf.setTimeZone(TimeZone.getTimeZone("GMT+9"));
        try {
            long time_pass = servertime_utc - sdf.parse(installDateTime_kst).getTime();
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "Time Pass: " + time_pass, 3, true);
            if (Math.abs(time_pass) < 60000) {
                return true;
            }
            return false;
        } catch (ParseException e) {
            e.printStackTrace();
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "checking new install : " + e.getMessage(), 3, false);
            return true;
        }
    }

    public void ReEngagementConversion(final RequestParameter parameter, final Context context, final DeeplinkReEngagementConversion dlReEngMntConversion) {
        DeviceIDManger.getInstance(context).getAndroidADID(context, new ADIDCallbackListener() {
            public void onResult(AdInfo adInfo) {
                boolean isLimitAdTrackingEnabled;
                try {
                    String url = CommonHttpManager.this.REENGAGEMENT_CONVERISON_REQ_URL_FOR_ADBRIX;
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ReEngagementConversion", 3, false);
                    JSONObject deeplink_info = new JSONObject(dlReEngMntConversion.getDeeplink_info());
                    RequestParameter requestParameter = parameter;
                    Context context = context;
                    String id = adInfo == null ? "" : adInfo.getId();
                    if (adInfo == null) {
                        isLimitAdTrackingEnabled = false;
                    } else {
                        isLimitAdTrackingEnabled = adInfo.isLimitAdTrackingEnabled();
                    }
                    String param = AESGetTrackParam.encrypt_hashkey(requestParameter.getReEngagementConversionTrackingParameter(context, deeplink_info, id, isLimitAdTrackingEnabled), parameter.getHashkey());
                    HashMap<String, String> paramValuePair = new HashMap<>();
                    paramValuePair.put("k", new StringBuilder(String.valueOf(parameter.getAppkey())).toString());
                    paramValuePair.put("j", param);
                    Context context2 = context;
                    final Context context3 = context;
                    final DeeplinkReEngagementConversion deeplinkReEngagementConversion = dlReEngMntConversion;
                    WeakReference<Thread> threadW = new WeakReference<>(new HttpsUrlConnectionThread(context2, 1, url, paramValuePair, new HttpCallbackListener() {
                        public void callback(String resultStr) {
                            long baseTime = -1;
                            if (resultStr == null) {
                                try {
                                    Exception exc = new Exception("ReEngagementConversion null Error");
                                    throw exc;
                                } catch (Exception e) {
                                    e.printStackTrace();
                                    Log.e(IgawConstant.QA_TAG, "ReEngagementConversion Callback error: " + e.getMessage());
                                    CommonHttpManager.this.storeForRetryReEngagementConversion(context3, deeplinkReEngagementConversion);
                                }
                            } else {
                                IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ReEngagementConversion > responseString : " + resultStr, 3, false);
                                RequestParameter atParam = RequestParameter.getATRequestParameter(context3);
                                JSONObject jSONObject = new JSONObject(resultStr);
                                try {
                                    if (jSONObject.has(HttpManager.SERVER_BASE_TIME)) {
                                        baseTime = jSONObject.getLong(HttpManager.SERVER_BASE_TIME);
                                        AppImpressionDAO.setServerBaseTimeOffset(context3, baseTime - System.currentTimeMillis());
                                    }
                                } catch (Exception e2) {
                                    e2.printStackTrace();
                                }
                                if (!jSONObject.getBoolean(HttpManager.RESULT) || jSONObject.isNull(HttpManager.DATA)) {
                                    CommonHttpManager.this.storeForRetryReEngagementConversion(context3, deeplinkReEngagementConversion);
                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ReEngagementConversion error : result false", 3, false);
                                    return;
                                }
                                JSONObject dataObject = new JSONObject(jSONObject.getString(HttpManager.DATA));
                                if (dataObject.has(HttpManager.CONVERSION_RESULT) && !dataObject.isNull(HttpManager.CONVERSION_RESULT)) {
                                    JSONObject conversion_result = dataObject.getJSONObject(HttpManager.CONVERSION_RESULT);
                                    int conversionKey = conversion_result.getInt("conversion_key");
                                    atParam.setADBrixUserInfo_reengagement_conversion_key((long) conversionKey);
                                    atParam.setADBrixUserInfo_reengagement_data(conversion_result.getString(HttpManager.POSTBACK_REENGAGEMENT_DATA));
                                    atParam.setADBrixUserInfo_reengagment_datetime(conversion_result.getString(HttpManager.POSTBACK_ENGAGEMENT_DATETIME));
                                    atParam.setConversionCache(conversionKey);
                                    atParam.setConversionCacheHistory(conversionKey, baseTime);
                                    atParam.setRetainedConversionCache(conversionKey);
                                }
                            }
                        }
                    }, false, false));
                    ((Thread) threadW.get()).setDaemon(true);
                    ((Thread) threadW.get()).start();
                } catch (Exception e) {
                    e.printStackTrace();
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ReEngagementConversion Exception:" + e.getMessage(), 0);
                    CommonHttpManager.this.storeForRetryReEngagementConversion(context, dlReEngMntConversion);
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void storeForRetryReEngagementConversion(final Context context, final DeeplinkReEngagementConversion dlReEngMntConversion) {
        Task.forResult(null).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Object, Void>() {
            public Void then(Task<Object> task) throws Exception {
                DeeplinkConversionRetryDAO dao = DeeplinkConversionRetryDAO.getDAO(context);
                if (dlReEngMntConversion.getRetryCnt() > 5) {
                    dao.removeDLReEngMntRetryConversion(dlReEngMntConversion.getKey());
                } else {
                    dao.updateOrInsertDLReEngMntConversionForRetry(dlReEngMntConversion.getKey(), dlReEngMntConversion.getConversionKey(), dlReEngMntConversion.getDeeplink_info());
                }
                return null;
            }
        }, (Executor) InternalAction.NETWORK_EXECUTOR);
    }

    public void ThirdPartyConversion(final RequestParameter parameter, final Context context, final DeeplinkReEngagementConversion thirdPartyConversion) {
        DeviceIDManger.getInstance(context).getAndroidADID(context, new ADIDCallbackListener() {
            public void onResult(AdInfo adInfo) {
                boolean isLimitAdTrackingEnabled;
                try {
                    String url = CommonHttpManager.this.THIRDPARTY_CONVERSION_REQ_URL_FOR_ADBRIX;
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ThirdPartyConversion", 3, false);
                    JSONObject deeplink_info = new JSONObject(thirdPartyConversion.getDeeplink_info());
                    RequestParameter requestParameter = parameter;
                    Context context = context;
                    String id = adInfo == null ? "" : adInfo.getId();
                    if (adInfo == null) {
                        isLimitAdTrackingEnabled = false;
                    } else {
                        isLimitAdTrackingEnabled = adInfo.isLimitAdTrackingEnabled();
                    }
                    String param = AESGetTrackParam.encrypt_hashkey(requestParameter.getReEngagementConversionTrackingParameter(context, deeplink_info, id, isLimitAdTrackingEnabled), parameter.getHashkey());
                    HashMap<String, String> paramValuePair = new HashMap<>();
                    paramValuePair.put("k", new StringBuilder(String.valueOf(parameter.getAppkey())).toString());
                    paramValuePair.put("j", param);
                    Context context2 = context;
                    final Context context3 = context;
                    final RequestParameter requestParameter2 = parameter;
                    final DeeplinkReEngagementConversion deeplinkReEngagementConversion = thirdPartyConversion;
                    WeakReference<Thread> threadW = new WeakReference<>(new HttpsUrlConnectionThread(context2, 1, url, paramValuePair, new HttpCallbackListener() {
                        public void callback(String resultStr) {
                            long baseTime = -1;
                            if (resultStr == null) {
                                try {
                                    throw new Exception("ThirdPartyConversion null Error");
                                } catch (Exception e) {
                                    e.printStackTrace();
                                    Log.e(IgawConstant.QA_TAG, "ThirdPartyConversion Callback error: " + e.getMessage());
                                    CommonHttpManager.this.storeForRetryThirdPartyConversion(context3, deeplinkReEngagementConversion);
                                }
                            } else {
                                IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ThirdPartyConversion > responseString : " + resultStr, 3, false);
                                RequestParameter atParam = RequestParameter.getATRequestParameter(context3);
                                JSONObject jSONObject = new JSONObject(resultStr);
                                try {
                                    if (jSONObject.has(HttpManager.SERVER_BASE_TIME)) {
                                        baseTime = jSONObject.getLong(HttpManager.SERVER_BASE_TIME);
                                        AppImpressionDAO.setServerBaseTimeOffset(context3, baseTime - System.currentTimeMillis());
                                    }
                                } catch (Exception e2) {
                                    e2.printStackTrace();
                                }
                                if (!jSONObject.getBoolean(HttpManager.RESULT) || jSONObject.isNull(HttpManager.DATA)) {
                                    CommonHttpManager.this.storeForRetryThirdPartyConversion(context3, deeplinkReEngagementConversion);
                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ThirdPartyConversion error : result false", 3, false);
                                    return;
                                }
                                JSONObject dataObject = new JSONObject(jSONObject.getString(HttpManager.DATA));
                                long referralKey = dataObject.getLong(HttpManager.REFERRALKEY);
                                int channelType = -1;
                                if (dataObject.has("channel_type") && !dataObject.isNull("channel_type")) {
                                    channelType = dataObject.getInt("channel_type");
                                }
                                IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, ThirdPartyConversion > referralKey : " + referralKey, 3, false);
                                if (referralKey != -1) {
                                    atParam.setADBrixUserInfo_ReferralKey(referralKey);
                                }
                                if (dataObject.has(HttpManager.SUBREFERRALKEY)) {
                                    String subreferralKey = dataObject.getString(HttpManager.SUBREFERRALKEY);
                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, ThirdPartyConversion > subreferralKey : " + subreferralKey, 3, false);
                                    atParam.setADBrixUserInfo_SubReferralKey(subreferralKey);
                                }
                                long adbrix_user_no = dataObject.getLong(HttpManager.ADBRIX_USER_NO);
                                IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, ThirdPartyConversion > adbrix_user_no : " + adbrix_user_no, 3, false);
                                atParam.setADBrixUserInfo(adbrix_user_no, System.currentTimeMillis());
                                if (dataObject.has(HttpManager.SHARD_NO) && !dataObject.isNull(HttpManager.SHARD_NO)) {
                                    int shardNo = dataObject.getInt(HttpManager.SHARD_NO);
                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, ThirdPartyConversion > shard_no : " + shardNo, 3, false);
                                    atParam.setADBrixUserInfo_ShardNo(shardNo);
                                }
                                if (channelType != -1) {
                                    atParam.setChannelType(channelType);
                                }
                                if (dataObject.has(HttpManager.INSTALL_DATETIME) && !dataObject.isNull(HttpManager.INSTALL_DATETIME)) {
                                    String installDatetime = dataObject.getString(HttpManager.INSTALL_DATETIME);
                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, ThirdPartyConversion > install_datetime : " + installDatetime, 3, false);
                                    requestParameter2.setNewInstall(CommonHttpManager.this.isNewInstall(context3, baseTime, installDatetime));
                                    atParam.setADBrixUserInfo_install_datetime(installDatetime);
                                }
                            }
                        }
                    }, false, false));
                    ((Thread) threadW.get()).setDaemon(true);
                    ((Thread) threadW.get()).start();
                } catch (Exception e) {
                    e.printStackTrace();
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ThirdPartyConversion Exception:" + e.getMessage(), 0);
                    CommonHttpManager.this.storeForRetryThirdPartyConversion(context, thirdPartyConversion);
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void storeForRetryThirdPartyConversion(final Context context, final DeeplinkReEngagementConversion thirdPartyConversion) {
        Task.forResult(null).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Object, Void>() {
            public Void then(Task<Object> task) throws Exception {
                DeeplinkConversionRetryDAO dao = DeeplinkConversionRetryDAO.getDAO(context);
                if (thirdPartyConversion.getRetryCnt() > 5) {
                    dao.removeThirdPartyRetryConversion(thirdPartyConversion.getKey());
                } else {
                    dao.updateOrInsertDLThirdPartyConversionForRetry(thirdPartyConversion.getKey(), thirdPartyConversion.getConversionKey(), thirdPartyConversion.getDeeplink_info());
                }
                return null;
            }
        }, (Executor) InternalAction.NETWORK_EXECUTOR);
    }

    public void reportingCrash(final RequestParameter parameter, final Context context, final List<JSONObject> err) {
        if (!CommonHelper.checkInternetConnection(context)) {
            restoreCrashInfo_Common(context, err);
        } else {
            InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                public void run() {
                    DeviceIDManger instance = DeviceIDManger.getInstance(context);
                    Context context = context;
                    final Context context2 = context;
                    final List list = err;
                    final RequestParameter requestParameter = parameter;
                    instance.getAndroidADID(context, new ADIDCallbackListener() {
                        public void onResult(AdInfo adInfo) {
                            final List<JSONObject> finalRemanentErr;
                            String adid = adInfo == null ? "" : adInfo.getId();
                            boolean isOverflowByte = false;
                            try {
                                ArrayList arrayList = new ArrayList();
                                IgawLogger.Logging(context2, IgawConstant.QA_TAG, "reportingCrash", 3);
                                String url = CommonHttpManager.this.TRACKING_REQUEST_URL_FOR_CRASHLTICS;
                                JSONArray pArr = new JSONArray();
                                for (JSONObject errJObject : list) {
                                    if (!isOverflowByte) {
                                        if (errJObject.has("iga_error")) {
                                            JSONArray arrThreadInfos = new JSONArray();
                                            String stringExceptionReason = "";
                                            if (errJObject.has("exception_reason")) {
                                                stringExceptionReason = errJObject.getString("exception_reason");
                                            }
                                            if (errJObject.has("thread_information")) {
                                                arrThreadInfos = errJObject.getJSONArray("thread_information");
                                            }
                                            pArr.put(requestParameter.getCrashParameter(adid, errJObject.getString("iga_error"), arrThreadInfos, stringExceptionReason));
                                        }
                                        if (errJObject.has("retry_cnt")) {
                                            errJObject.put("retry_cnt", errJObject.getInt("retry_cnt") + 1);
                                            if (errJObject.getInt("retry_cnt") >= 9) {
                                                list.remove(errJObject);
                                            }
                                        }
                                        if (((double) pArr.toString().length()) > 100000.0d) {
                                            IgawLogger.Logging(context2, IgawConstant.QA_TAG, "ADBrixTracer, Overflow of limited stringByte, so the remanent crash infos not gonna send to server in this time" + list.toString(), 4, true);
                                            isOverflowByte = true;
                                        }
                                    } else if (errJObject.has("iga_error")) {
                                        arrayList.add(errJObject);
                                    }
                                }
                                if (!isOverflowByte) {
                                    List<String> crashInfos = CrashDAO.getCrashes(context2);
                                    if (crashInfos != null && crashInfos.size() > 0) {
                                        try {
                                            for (String pJsonString : crashInfos) {
                                                JSONObject jSONObject = new JSONObject(pJsonString);
                                                if (!isOverflowByte) {
                                                    if (jSONObject.has("iga_error")) {
                                                        JSONArray arrThreadInfos2 = new JSONArray();
                                                        String stringExceptionReason2 = "";
                                                        if (jSONObject.has("exception_reason")) {
                                                            stringExceptionReason2 = jSONObject.getString("exception_reason");
                                                        }
                                                        if (jSONObject.has("thread_information")) {
                                                            arrThreadInfos2 = jSONObject.getJSONArray("thread_information");
                                                        }
                                                        pArr.put(requestParameter.getCrashParameter(adid, jSONObject.getString("iga_error"), arrThreadInfos2, stringExceptionReason2));
                                                    }
                                                    if (jSONObject.has("retry_cnt")) {
                                                        jSONObject.put("retry_cnt", jSONObject.getInt("retry_cnt") + 1);
                                                        if (jSONObject.getInt("retry_cnt") >= 9) {
                                                            crashInfos.remove(pJsonString);
                                                        }
                                                    }
                                                    list.add(jSONObject);
                                                    if (((double) pArr.toString().length()) > 100000.0d) {
                                                        IgawLogger.Logging(context2, IgawConstant.QA_TAG, "ADBrixTracer, Overflow of limited stringByte, so the remanent crash infos not gonna send to server in this time" + list.toString(), 4, true);
                                                        isOverflowByte = true;
                                                    }
                                                } else if (jSONObject.has("iga_error")) {
                                                    arrayList.add(jSONObject);
                                                }
                                            }
                                        } catch (Exception e) {
                                            e.printStackTrace();
                                        }
                                    }
                                }
                                if (isOverflowByte) {
                                    finalRemanentErr = new ArrayList<>(arrayList);
                                } else {
                                    finalRemanentErr = new ArrayList<>();
                                }
                                IgawLogger.Logging(context2, IgawConstant.QA_TAG, "Total Crash Param " + pArr.toString(), 2, true);
                                try {
                                    Context context = context2;
                                    String jSONArray = pArr.toString();
                                    final Context context2 = context2;
                                    final List list = list;
                                    WeakReference weakReference = new WeakReference(new JsonHttpsUrlConnectionThread(context, 1, url, jSONArray, new HttpCallbackListener() {
                                        public void callback(String result) {
                                            if (result != null) {
                                                try {
                                                    if (!result.equals("")) {
                                                        IgawLogger.Logging(context2, IgawConstant.QA_TAG, "ADBrixTracer, reportingCrash response result : " + result, 3, false);
                                                        JSONObject jsonObject = new JSONObject(result);
                                                        if (!jsonObject.has(ServerProtocol.CODE_KEY) || jsonObject.isNull(ServerProtocol.CODE_KEY)) {
                                                            IgawLogger.Logging(context2, IgawConstant.QA_TAG, "reportingCrash error : no result", 3, false);
                                                            CommonHttpManager.this.restoreCrashInfo_Common(context2, list);
                                                            return;
                                                        } else if (jsonObject.getInt(ServerProtocol.CODE_KEY) == 0) {
                                                            IgawLogger.Logging(context2, IgawConstant.QA_TAG, "reportingCrash succeeded : result 0", 2, true);
                                                            if (finalRemanentErr.size() > 0) {
                                                                CommonHttpManager.this.restoreCrashInfo_Common(context2, finalRemanentErr);
                                                                return;
                                                            }
                                                            return;
                                                        } else {
                                                            IgawLogger.Logging(context2, IgawConstant.QA_TAG, "reportingCrash failed : result " + jsonObject.getInt(ServerProtocol.CODE_KEY), 2, true);
                                                            CommonHttpManager.this.restoreCrashInfo_Common(context2, list);
                                                            return;
                                                        }
                                                    }
                                                } catch (Exception e) {
                                                    e.printStackTrace();
                                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, e.getMessage(), 0);
                                                    CommonHttpManager.this.restoreCrashInfo_Common(context2, list);
                                                    return;
                                                }
                                            }
                                            CommonHttpManager.this.restoreCrashInfo_Common(context2, list);
                                            throw new Exception("responseResult null Error");
                                        }
                                    }, false, false));
                                    ((Thread) weakReference.get()).setDaemon(true);
                                    ((Thread) weakReference.get()).start();
                                } catch (Exception e2) {
                                    e2.printStackTrace();
                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, e2.toString(), 0);
                                    CommonHttpManager.this.restoreCrashInfo_Common(context2, list);
                                }
                            } catch (Exception e3) {
                                e3.printStackTrace();
                                IgawLogger.Logging(context2, IgawConstant.QA_TAG, e3.toString(), 0);
                                CommonHttpManager.this.restoreCrashInfo_Common(context2, list);
                            }
                        }
                    });
                }
            });
        }
    }

    /* access modifiers changed from: protected */
    public void restoreCrashInfo_Common(Context context, List<JSONObject> err) {
        int pCount = 1;
        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixTracer, save Crash infos : " + err.toString(), 3, false);
        for (JSONObject errJObject : err) {
            SimpleDateFormat s = new SimpleDateFormat("yyyy_MM_dd_HHmmss", Locale.US);
            s.setTimeZone(TimeZone.getDefault());
            String timestamp = "igaworks_crash_" + pCount + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR + s.format(new Date());
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixTracer, save Crash infos to SP key : " + timestamp + "values :" + errJObject.toString(), 3, false);
            CrashDAO.updateCrash(context, timestamp, errJObject.toString());
            pCount++;
        }
    }
}