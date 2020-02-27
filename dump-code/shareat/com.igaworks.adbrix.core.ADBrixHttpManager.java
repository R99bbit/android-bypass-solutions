package com.igaworks.adbrix.core;

import android.content.Context;
import android.content.SharedPreferences.Editor;
import android.graphics.Bitmap;
import android.os.Build.VERSION;
import android.os.CountDownTimer;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;
import com.facebook.appevents.AppEventsConstants;
import com.igaworks.adbrix.cpe.CPECompletionHandler;
import com.igaworks.adbrix.db.ConversionDAOForRetryCompletion;
import com.igaworks.adbrix.db.DailyPlayDAO;
import com.igaworks.adbrix.interfaces.ParticipationProgressCallbackListener;
import com.igaworks.adbrix.json.JSON2ScheduleConverter;
import com.igaworks.adbrix.model.DailyPlay;
import com.igaworks.adbrix.model.Engagement;
import com.igaworks.adbrix.model.Promotion;
import com.igaworks.adbrix.model.ScheduleContainer;
import com.igaworks.adbrix.model.Theme;
import com.igaworks.core.AESGetTrackParam;
import com.igaworks.core.AdvertisingIdClient.ADIDCallbackListener;
import com.igaworks.core.AdvertisingIdClient.AdInfo;
import com.igaworks.core.DeviceIDManger;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;
import com.igaworks.dao.AppImpressionDAO;
import com.igaworks.dao.tracking.TrackingActivityModel;
import com.igaworks.interfaces.HttpCallbackListener;
import com.igaworks.net.CommonHttpManager;
import com.igaworks.net.HttpManager;
import com.igaworks.net.HttpsUrlConnectionThread;
import com.igaworks.util.CommonHelper;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.Task;
import com.igaworks.util.image.ImageCacheFactory;
import com.igaworks.util.image.ImageDownloadAsyncCallback;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map.Entry;
import java.util.concurrent.Executor;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class ADBrixHttpManager extends CommonHttpManager {
    private static ADBrixHttpManager manager;
    /* access modifiers changed from: private */
    public static boolean onGetSchedule = false;
    public static OnGetSchedule onGetScheduleEvent;
    public static ScheduleContainer schedule;
    /* access modifiers changed from: private */
    public String COMPLETE_CPE_REQUEST_URL_FOR_ADBrix = (cpn_domain + "Campaign/Complete");
    private String PARTICIPATION_PROGRESS_REQUEST_URL_FOR_ADBrix = (cpn_domain + "CampaignVer2/GetCampaignInfo");
    private String SCHEDULE_REQUEST_URL_FOR_ADBrix = (cpn_domain + "CampaignVer2/GetSchedule");

    private ADBrixHttpManager() {
    }

    public static ADBrixHttpManager getManager(Context context) {
        if (manager == null) {
            manager = new ADBrixHttpManager();
        }
        return manager;
    }

    public void completeCPECallForADBrix(RequestParameter parameter, Context context, ArrayList<TrackingActivityModel> activity_info_list, ArrayList<TrackingActivityModel> imp_info_list, ArrayList<Integer> complete_conversion_list) {
        try {
            final Context context2 = context;
            final ArrayList<TrackingActivityModel> arrayList = activity_info_list;
            final ArrayList<TrackingActivityModel> arrayList2 = imp_info_list;
            final RequestParameter requestParameter = parameter;
            final ArrayList<Integer> arrayList3 = complete_conversion_list;
            DeviceIDManger.getInstance(context).getAndroidADID(context, new ADIDCallbackListener() {
                public void onResult(AdInfo adInfo) {
                    boolean isLimitAdTrackingEnabled;
                    try {
                        String url = ADBrixHttpManager.this.COMPLETE_CPE_REQUEST_URL_FOR_ADBrix;
                        IgawLogger.Logging(context2, IgawConstant.QA_TAG, "completeCPECallForADBrix", 3, false);
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
                        ArrayList arrayList = arrayList3;
                        String id = adInfo == null ? "" : adInfo.getId();
                        if (adInfo == null) {
                            isLimitAdTrackingEnabled = false;
                        } else {
                            isLimitAdTrackingEnabled = adInfo.isLimitAdTrackingEnabled();
                        }
                        String param = AESGetTrackParam.encrypt_hashkey(requestParameter.getTrackingParameterForADBrix(context, str_activity_info_list, str_imp_info_list, arrayList, id, isLimitAdTrackingEnabled), requestParameter.getHashkey());
                        HashMap<String, String> paramValuePair = new HashMap<>();
                        paramValuePair.put("k", new StringBuilder(String.valueOf(requestParameter.getAppkey())).toString());
                        paramValuePair.put("j", param);
                        Context context2 = context2;
                        final Context context3 = context2;
                        final ArrayList arrayList2 = arrayList;
                        final ArrayList arrayList3 = arrayList2;
                        final ArrayList arrayList4 = arrayList3;
                        HttpsUrlConnectionThread httpsUrlConnectionThread = new HttpsUrlConnectionThread(context2, 1, url, paramValuePair, new HttpCallbackListener() {
                            public void callback(String resultStr) {
                                long baseTime = -1;
                                if (resultStr == null) {
                                    try {
                                        throw new Exception("complete CPE null Error");
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                        Log.e(IgawConstant.QA_TAG, "completeCPECallForADBrix Callback error: " + e.getMessage());
                                        ADBrixHttpManager.this.restoreTrackingInfo_Common(context3, arrayList2, arrayList3);
                                        ADBrixHttpManager.this.restoreCPEConversionList(context3, arrayList4);
                                    }
                                } else {
                                    IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixTracer, callbackReferrerADBrix > responseString : " + resultStr, 3, false);
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
                                        ADBrixHttpManager.this.restoreTrackingInfo_Common(context3, arrayList2, arrayList3);
                                        ADBrixHttpManager.this.restoreCPEConversionList(context3, arrayList4);
                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "complete cpe error : result false", 3, false);
                                        return;
                                    }
                                    JSONObject dataObject = new JSONObject(jSONObject.getString(HttpManager.DATA));
                                    if (dataObject.has(HttpManager.CONVERSION_RESULT) && !dataObject.isNull(HttpManager.CONVERSION_RESULT)) {
                                        JSONArray results = dataObject.getJSONArray(HttpManager.CONVERSION_RESULT);
                                        Editor inputConversionKey = context3.getSharedPreferences("completeConversions", 0).edit();
                                        for (int i = 0; i < results.length(); i++) {
                                            JSONObject result = results.getJSONObject(i);
                                            if (result.has("conversion_key") && !result.isNull("conversion_key") && result.has("result_code") && !result.isNull("result_code")) {
                                                int conversionKey = result.getInt("conversion_key");
                                                int resultCode = result.getInt("result_code");
                                                Engagement engagement = null;
                                                DailyPlay dailyPlay = null;
                                                Iterator<Engagement> it = ADBrixHttpManager.schedule.getSchedule().getEngagements().iterator();
                                                while (true) {
                                                    if (it.hasNext()) {
                                                        Engagement eng = it.next();
                                                        if (eng.getConversionKey() == conversionKey) {
                                                            engagement = eng;
                                                            break;
                                                        }
                                                    } else {
                                                        break;
                                                    }
                                                }
                                                Iterator<DailyPlay> it2 = ADBrixHttpManager.schedule.getSchedule().getReEngagement().getDailyPlay().iterator();
                                                while (true) {
                                                    if (it2.hasNext()) {
                                                        DailyPlay dp = it2.next();
                                                        if (dp.getConversionKey() == conversionKey) {
                                                            dailyPlay = dp;
                                                            break;
                                                        }
                                                    } else {
                                                        break;
                                                    }
                                                }
                                                if (resultCode == 1) {
                                                    atParam.setConversionCache(conversionKey);
                                                    atParam.setConversionCacheHistory(conversionKey, baseTime);
                                                    atParam.setRetainedConversionCache(conversionKey);
                                                    if (engagement != null) {
                                                        final Engagement cEng = engagement;
                                                        String msg = cEng.getDisplayData().getCompleteMessage();
                                                        if (engagement.getDisplayData().getCompleteToastMSec() > 0 && msg != null && msg.length() > 0 && !msg.equals("null")) {
                                                            Handler handler = new Handler(Looper.getMainLooper());
                                                            final Context context = context3;
                                                            final String str = msg;
                                                            AnonymousClass1 r0 = new Runnable() {
                                                                public void run() {
                                                                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "callback complete cpe > msg : " + str + ", duration : " + cEng.getDisplayData().getCompleteToastMSec(), 3, false);
                                                                    ADBrixHttpManager.this.makeCompleteToast(context, (long) cEng.getDisplayData().getCompleteToastMSec(), str);
                                                                }
                                                            };
                                                            handler.post(r0);
                                                        }
                                                        IgawLogger.Logging(context3, IgawConstant.QA_TAG, "callback complete cpe > key : " + conversionKey, 3, false);
                                                    }
                                                    if (dailyPlay != null) {
                                                        DailyPlayDAO.getInstance().setPendingConversionKey(context3, -1);
                                                        DailyPlayDAO.getInstance().setLatestConversionKey(context3, dailyPlay.getConversionKey());
                                                    }
                                                } else if (resultCode != 7000) {
                                                    ADBrixHttpManager.this.restoreCPESingleConversion(context3, conversionKey, resultCode);
                                                } else if (dailyPlay != null) {
                                                    if (DailyPlayDAO.getInstance().getPendingConversionKey(context3) == dailyPlay.getConversionKey()) {
                                                        DailyPlayDAO.getInstance().setPendingConversionKey(context3, -1);
                                                    }
                                                    int waiting_time = -1;
                                                    if (result.has(HttpManager.WAITING_TIME) && !result.isNull(HttpManager.WAITING_TIME)) {
                                                        waiting_time = result.getInt(HttpManager.WAITING_TIME);
                                                    }
                                                    DailyPlayDAO.getInstance().setWaitingTime(context3, waiting_time);
                                                }
                                                inputConversionKey.remove(conversionKey);
                                                inputConversionKey.commit();
                                            }
                                        }
                                    }
                                }
                            }
                        }, false, true);
                        WeakReference weakReference = new WeakReference(httpsUrlConnectionThread);
                        ((Thread) weakReference.get()).setDaemon(true);
                        ((Thread) weakReference.get()).start();
                    } catch (Exception e) {
                        e.printStackTrace();
                        IgawLogger.Logging(context2, IgawConstant.QA_TAG, e.getMessage(), 0);
                        ADBrixHttpManager.this.restoreTrackingInfo_Common(context2, arrayList, arrayList2);
                        ADBrixHttpManager.this.restoreCPEConversionList(context2, arrayList3);
                    }
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
            IgawLogger.Logging(context, IgawConstant.QA_TAG, e.getMessage(), 0);
            restoreTrackingInfo_Common(context, activity_info_list, imp_info_list);
            restoreCPEConversionList(context, complete_conversion_list);
        }
    }

    public void getScheduleForADBrix(RequestParameter parameter, Context context, String puid, ScheduleContainer scheduleContainer) {
        final String url = this.SCHEDULE_REQUEST_URL_FOR_ADBrix;
        final Context context2 = context;
        final RequestParameter requestParameter = parameter;
        final String str = puid;
        new Thread(new Runnable() {
            public void run() {
                try {
                    DeviceIDManger instance = DeviceIDManger.getInstance(context2);
                    Context context = context2;
                    final Context context2 = context2;
                    final RequestParameter requestParameter = requestParameter;
                    final String str = str;
                    final String str2 = url;
                    instance.getAndroidADID(context, new ADIDCallbackListener() {
                        public void onResult(AdInfo adInfo) {
                            if (adInfo == null) {
                                Log.e(IgawConstant.QA_TAG, "@getScheduleForADBrix: google_ad_id is null");
                                ADBrixHttpManager.onGetSchedule = false;
                            } else if (ADBrixHttpManager.onGetSchedule) {
                                IgawLogger.Logging(context2, IgawConstant.QA_TAG, "onGetSchedule already called.", 3);
                            } else {
                                try {
                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, "getScheduleForADBrix > getSchedule call send.", 3, false);
                                    Locale defaultLocale = Locale.getDefault();
                                    String os = "";
                                    if (VERSION.RELEASE != null && !VERSION.RELEASE.equalsIgnoreCase("")) {
                                        os = VERSION.RELEASE;
                                    }
                                    HashMap<String, String> paramValuePair = new HashMap<>();
                                    paramValuePair.put("k", new StringBuilder(String.valueOf(requestParameter.getAppkey())).toString());
                                    paramValuePair.put("la", defaultLocale.getLanguage());
                                    paramValuePair.put("co", defaultLocale.getCountry());
                                    paramValuePair.put("os", "a_" + os);
                                    paramValuePair.put("version", "a_" + os);
                                    paramValuePair.put(RequestParameter.PUID, str);
                                    paramValuePair.put(RequestParameter.GOOGLE_AD_ID, adInfo.getId());
                                    String checksum = AppEventsConstants.EVENT_PARAM_VALUE_NO;
                                    if (!(ADBrixHttpManager.schedule == null || ADBrixHttpManager.schedule.getCheckSum() == null)) {
                                        checksum = ADBrixHttpManager.schedule.getCheckSum();
                                    }
                                    paramValuePair.put("checksum", checksum);
                                    Context context = context2;
                                    String str = str2;
                                    final Context context2 = context2;
                                    final RequestParameter requestParameter = requestParameter;
                                    WeakReference<Thread> threadW = new WeakReference<>(new HttpsUrlConnectionThread(context, 1, str, paramValuePair, new HttpCallbackListener() {
                                        public void callback(String result) {
                                            ADBrixHttpManager.onGetSchedule = false;
                                            if (result == null) {
                                                try {
                                                    throw new Exception("responseResult null Error");
                                                } catch (Exception e) {
                                                    e.printStackTrace();
                                                    ADBrixHttpManager.onGetSchedule = false;
                                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, e.getMessage(), 0);
                                                }
                                            } else {
                                                IgawLogger.Logging(context2, IgawConstant.QA_TAG, "ADBrixTracer, get schedule response result : " + result, 3);
                                                try {
                                                    JSONObject jSONObject = new JSONObject(result);
                                                    if (jSONObject.has(HttpManager.SERVER_BASE_TIME)) {
                                                        AppImpressionDAO.setServerBaseTimeOffset(context2, jSONObject.getLong(HttpManager.SERVER_BASE_TIME) - System.currentTimeMillis());
                                                    }
                                                } catch (Exception e2) {
                                                    e2.printStackTrace();
                                                }
                                                try {
                                                    ADBrixHttpManager.schedule = JSON2ScheduleConverter.json2ScheduleV2(context2, result);
                                                    Context context = context2;
                                                    StringBuilder sb = new StringBuilder("ADBrixTracer, schedule received, local cache: ");
                                                    String str = ADBrixHttpManager.schedule != null ? "exist" : "null";
                                                    r1 = IgawConstant.QA_TAG;
                                                    IgawLogger.Logging(context, IgawConstant.QA_TAG, sb.append(str).toString(), 3, false);
                                                    try {
                                                        List<Engagement> engagementList = ADBrixHttpManager.schedule.getSchedule().getEngagements();
                                                        if (engagementList != null && engagementList.size() > 0) {
                                                            for (Engagement engagement : engagementList) {
                                                                if (engagement.isAllowDuplication()) {
                                                                    requestParameter.setAllowDuplicationConversion(engagement.getConversionKey(), engagement.getParentConversionKey());
                                                                }
                                                            }
                                                        }
                                                    } catch (Exception e3) {
                                                        Log.e(IgawConstant.QA_TAG, "Update allowDuplication list error: " + e3.getMessage());
                                                        e3.printStackTrace();
                                                    }
                                                    try {
                                                        List<DailyPlay> DailyPlayStepList = ADBrixHttpManager.schedule.getSchedule().getReEngagement().getDailyPlay();
                                                        if (DailyPlayStepList != null && DailyPlayStepList.size() > 0) {
                                                            int waitTime = DailyPlayStepList.get(0).getPlayTime();
                                                            Log.d(IgawConstant.QA_TAG, "DL Play time = " + waitTime);
                                                            DailyPlayDAO.getInstance().setPlayTime(context2, waitTime);
                                                        }
                                                    } catch (Exception e_wt) {
                                                        Log.e(IgawConstant.QA_TAG, "Update DL waiting time error: " + e_wt.getMessage());
                                                    }
                                                    if (ADBrixHttpManager.onGetScheduleEvent != null) {
                                                        ADBrixHttpManager.onGetScheduleEvent.onGetSchedule(context2, true);
                                                    }
                                                    RequestParameter parameter = RequestParameter.getATRequestParameter(context2);
                                                    if (parameter.getReferralKey() != -1) {
                                                        CPECompletionHandler.restoreCPEAction(context2, parameter, ADBrixHttpManager.this);
                                                    }
                                                    if (ADBrixHttpManager.schedule != null) {
                                                        if (!(ADBrixHttpManager.schedule.getSchedule() == null || ADBrixHttpManager.schedule.getSchedule().getMedia() == null || ADBrixHttpManager.schedule.getSchedule().getMedia().getTheme() == null)) {
                                                            Theme theme = ADBrixHttpManager.schedule.getSchedule().getMedia().getTheme();
                                                            ADBrixHttpManager.this.preDownloadImage(context2, theme.getCirclePlayBtn());
                                                            ADBrixHttpManager.this.preDownloadImage(context2, theme.getCloseBtn());
                                                            ADBrixHttpManager.this.preDownloadImage(context2, theme.getMissionCheckOff());
                                                            ADBrixHttpManager.this.preDownloadImage(context2, theme.getMissionCheckOn());
                                                            ADBrixHttpManager.this.preDownloadImage(context2, theme.getPlayBtnAreaBG());
                                                            ADBrixHttpManager.this.preDownloadImage(context2, theme.getSelectedAppArrow());
                                                            ADBrixHttpManager.this.preDownloadImage(context2, theme.getSlideLeftBtn());
                                                            ADBrixHttpManager.this.preDownloadImage(context2, theme.getSlideRightBtn());
                                                            ADBrixHttpManager.this.preDownloadImage(context2, theme.getSquarePlayBtn());
                                                            ADBrixHttpManager.this.preDownloadImage(context2, theme.getStepArrow());
                                                        }
                                                        for (Promotion promotion : ADBrixHttpManager.schedule.getSchedule().getPromotions()) {
                                                            if (promotion.getDisplay() != null) {
                                                                try {
                                                                    if (promotion.getDisplay().getSlide().getResource() != null) {
                                                                        for (String item : promotion.getDisplay().getSlide().getResource()) {
                                                                            ADBrixHttpManager.this.preDownloadImage(context2, item);
                                                                        }
                                                                    }
                                                                    ADBrixHttpManager.this.preDownloadImage(context2, promotion.getDisplay().getIcon().getResource());
                                                                } catch (Exception e4) {
                                                                    e4.printStackTrace();
                                                                }
                                                            }
                                                        }
                                                    }
                                                } catch (Exception e5) {
                                                    ADBrixHttpManager.schedule = null;
                                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, "ADBrixTracer, schedule received, but parsing error occurred -> " + e5.toString(), 3, false);
                                                }
                                            }
                                        }
                                    }, false, false));
                                    ADBrixHttpManager.onGetSchedule = true;
                                    ((Thread) threadW.get()).setDaemon(true);
                                    ((Thread) threadW.get()).start();
                                } catch (Exception e) {
                                    e.printStackTrace();
                                    ADBrixHttpManager.onGetSchedule = false;
                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, e.getMessage(), 0);
                                }
                            }
                        }
                    });
                } catch (Exception e) {
                    e.printStackTrace();
                    ADBrixHttpManager.onGetSchedule = false;
                }
            }
        }).start();
    }

    public void getParticipationProgressForADBrix(RequestParameter parameter, Context context, String appKey, int campaignKey, String puid, String usn, ParticipationProgressCallbackListener listener) {
        final String url = this.PARTICIPATION_PROGRESS_REQUEST_URL_FOR_ADBrix;
        final Context context2 = context;
        final int i = campaignKey;
        final String str = usn;
        final String str2 = appKey;
        final String str3 = puid;
        final ParticipationProgressCallbackListener participationProgressCallbackListener = listener;
        new Thread(new Runnable() {
            public void run() {
                try {
                    DeviceIDManger instance = DeviceIDManger.getInstance(context2);
                    Context context = context2;
                    final Context context2 = context2;
                    final int i = i;
                    final String str = str;
                    final String str2 = str2;
                    final String str3 = str3;
                    final String str4 = url;
                    final ParticipationProgressCallbackListener participationProgressCallbackListener = participationProgressCallbackListener;
                    instance.getAndroidADID(context, new ADIDCallbackListener() {
                        public void onResult(AdInfo adInfo) {
                            if (adInfo != null) {
                                try {
                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, "getParticipationProgressForADBrix > getParticipationProgress call send. ck = " + i + ", google adid = " + adInfo.getId() + ", usn = " + str + ", appKey = " + str2, 3, true);
                                    HashMap<String, String> paramValuePair = new HashMap<>();
                                    paramValuePair.put("ak", str2);
                                    paramValuePair.put("ck", new StringBuilder(String.valueOf(i)).toString());
                                    paramValuePair.put(RequestParameter.PUID, str3);
                                    paramValuePair.put(RequestParameter.GOOGLE_AD_ID, adInfo.getId());
                                    paramValuePair.put("usn", str);
                                    Context context = context2;
                                    String str = str4;
                                    final Context context2 = context2;
                                    final ParticipationProgressCallbackListener participationProgressCallbackListener = participationProgressCallbackListener;
                                    WeakReference<Thread> threadW = new WeakReference<>(new HttpsUrlConnectionThread(context, 1, str, paramValuePair, new HttpCallbackListener() {
                                        public void callback(String result) {
                                            if (result == null) {
                                                try {
                                                    throw new Exception("responseResult null Error");
                                                } catch (Exception e) {
                                                    e.printStackTrace();
                                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, e.getMessage(), 0);
                                                }
                                            } else {
                                                try {
                                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, "ADBrixTracer, get participation progress result : " + result, 3);
                                                    participationProgressCallbackListener.callback(JSON2ScheduleConverter.json2ParticipationProgressModel(result));
                                                } catch (Exception e2) {
                                                    participationProgressCallbackListener.callback(null);
                                                    e2.printStackTrace();
                                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, "ADBrixTracer, get participation progress error : " + e2.toString(), 3);
                                                }
                                            }
                                        }
                                    }, false, true));
                                    ((Thread) threadW.get()).setDaemon(true);
                                    ((Thread) threadW.get()).start();
                                } catch (Exception e) {
                                    e.printStackTrace();
                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, "ADBrixTracer, get participation progress error : " + e.toString(), 3);
                                }
                            } else {
                                Log.e(IgawConstant.QA_TAG, "@getParticipationProgressForADBrix: google_ad_is is null");
                            }
                        }
                    });
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    public String getJSONParam(HashMap<String, String> params) {
        JSONObject obj = new JSONObject();
        if (params != null) {
            try {
                if (params.size() > 0) {
                    for (Entry<String, String> entry : params.entrySet()) {
                        obj.put(entry.getKey(), entry.getValue());
                    }
                }
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }
        return obj.toString();
    }

    /* access modifiers changed from: private */
    public void restoreCPESingleConversion(final Context context, final int conversion, final int resultCode) {
        Task.forResult(null).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Object, Void>() {
            public Void then(Task<Object> task) throws Exception {
                ConversionDAOForRetryCompletion.getDAO(context).updateOrInsertConversionForRetry(conversion);
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "callback complete cpe error occurred : resultCode = " + resultCode, 3, false);
                return null;
            }
        }, (Executor) Task.BACKGROUND_EXECUTOR);
    }

    /* access modifiers changed from: private */
    public void restoreCPEConversionList(final Context context, final ArrayList<Integer> complete_conversion_list) {
        Task.forResult(null).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Object, Void>() {
            public Void then(Task<Object> task) throws Exception {
                ConversionDAOForRetryCompletion retryDao = ConversionDAOForRetryCompletion.getDAO(context);
                Iterator it = complete_conversion_list.iterator();
                while (it.hasNext()) {
                    retryDao.updateOrInsertConversionForRetry(((Integer) it.next()).intValue());
                }
                return null;
            }
        }, (Executor) Task.BACKGROUND_EXECUTOR);
    }

    public void makeCompleteToast(Context context, long msec, String msg) {
        if (msec > 0 && msg != null && msg.length() > 0 && !msg.equals("null")) {
            final Toast popupToast = Toast.makeText(context, msg, 0);
            popupToast.show();
            new CountDownTimer(msec, 100) {
                public void onTick(long millisUntilFinished) {
                    popupToast.show();
                }

                public void onFinish() {
                    popupToast.show();
                }
            }.start();
        }
    }

    /* access modifiers changed from: private */
    public void preDownloadImage(Context context, String url) {
        if (url != null) {
            try {
                if (url.length() >= 1 && CommonHelper.CheckPermissionForCommonSDK(context)) {
                    String nUrl = url.trim();
                    try {
                        CPECompletionHandler.getImageDownloader(context).download(nUrl, null, null, null, new ImageDownloadAsyncCallback(nUrl, null, ImageCacheFactory.getInstance().get("imagecache"), null) {
                            public void onResultCustom(Bitmap bitmap) {
                                bitmap.recycle();
                            }
                        });
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }
}