package com.igaworks.adbrix.impl;

import android.app.Activity;
import android.content.Context;
import android.os.SystemClock;
import android.util.Log;
import com.igaworks.IgawCommon;
import com.igaworks.adbrix.core.ADBrixHttpManager;
import com.igaworks.adbrix.core.OnGetSchedule;
import com.igaworks.adbrix.cpe.CPECompletionHandler;
import com.igaworks.adbrix.cpe.PromotionHandler;
import com.igaworks.adbrix.db.ConversionDAOForRetryCompletion;
import com.igaworks.adbrix.db.DailyPlayDAO;
import com.igaworks.adbrix.db.ScheduleDAO;
import com.igaworks.adbrix.interfaces.ADBrixCallbackListener;
import com.igaworks.adbrix.interfaces.ADBrixInterface;
import com.igaworks.adbrix.interfaces.ADBrixInterface.CohortVariable;
import com.igaworks.adbrix.interfaces.PromotionActionListener;
import com.igaworks.adbrix.model.Engagement;
import com.igaworks.adbrix.model.RetryCompleteConversion;
import com.igaworks.commerce.IgawCommerce;
import com.igaworks.commerce.IgawCommerce.Currency;
import com.igaworks.commerce.IgawCommerce.IgawPaymentMethod;
import com.igaworks.commerce.IgawCommerce.IgawSharingChannel;
import com.igaworks.commerce.IgawCommerceItemModel;
import com.igaworks.commerce.IgawCommerceProductCategoryModel;
import com.igaworks.commerce.IgawCommerceProductModel;
import com.igaworks.core.DeviceIDManger;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;
import com.igaworks.dao.CPESessionImpressionDAO;
import com.igaworks.dao.CohortDAO;
import com.igaworks.dao.tracking.TrackingActivityModel;
import com.igaworks.dao.tracking.TrackingActivitySQLiteDB;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.impl.InternalAction;
import com.igaworks.interfaces.CommonActivityListener;
import com.igaworks.interfaces.CommonInterface;
import com.igaworks.interfaces.ExtendedCommonActivityListener;
import com.igaworks.net.HttpManager;
import com.igaworks.util.CommonHelper;
import com.igaworks.util.bolts_task.Capture;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.Task;
import io.fabric.sdk.android.services.settings.SettingsJsonConstants;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.Executor;
import org.json.JSONArray;
import org.json.JSONObject;

class ADBrixFrameworkImpl extends CommonFrameworkImpl implements ADBrixInterface, CommonActivityListener, ExtendedCommonActivityListener {
    /* access modifiers changed from: private */
    public static int DL_PLAY_TIME_PASS = 0;
    private static long DL_SESSION_START_TIME = 0;
    /* access modifiers changed from: private */
    public static Object lockObj = new Object();
    public static boolean onProcessDailyPlay = false;
    /* access modifiers changed from: private */
    public static int retryTime = 0;
    private AdPopCornDailyPlayTimerTask dailyPlayCheckTask;
    protected ADBrixHttpManager httpManager = null;
    private Timer timer;

    class AdPopCornDailyPlayTimerTask extends TimerTask {
        AdPopCornDailyPlayTimerTask() {
        }

        /* JADX WARNING: Code restructure failed: missing block: B:14:?, code lost:
            r0 = com.igaworks.adbrix.core.ADBrixHttpManager.schedule.getSchedule().getReEngagement().getDailyPlay();
         */
        /* JADX WARNING: Code restructure failed: missing block: B:15:0x0037, code lost:
            if (r0 == null) goto L_0x00c3;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:16:0x0039, code lost:
            r2 = (int) com.igaworks.core.RequestParameter.getATRequestParameter(com.igaworks.adbrix.impl.ADBrixFrameworkImpl.getContext()).getReferralKey();
         */
        /* JADX WARNING: Code restructure failed: missing block: B:17:0x0046, code lost:
            if (r2 <= 0) goto L_0x00af;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:19:0x004c, code lost:
            if (com.igaworks.adbrix.impl.ADBrixFrameworkImpl.getContext() == null) goto L_0x0079;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:20:0x004e, code lost:
            com.igaworks.adbrix.db.DailyPlayDAO.getInstance().saveLastConversionDateTime(com.igaworks.adbrix.impl.ADBrixFrameworkImpl.getContext());
            com.igaworks.core.IgawLogger.Logging(com.igaworks.adbrix.impl.ADBrixFrameworkImpl.getContext(), com.igaworks.core.IgawConstant.QA_TAG, "ADBrixManager >> ReEngagement DailyPlayStepList size: " + r0.size(), 3, true);
         */
        /* JADX WARNING: Code restructure failed: missing block: B:21:0x0079, code lost:
            com.igaworks.adbrix.cpe.DailyPlayHandler.checkandComplete(com.igaworks.adbrix.impl.ADBrixFrameworkImpl.getContext(), r0, r2);
            com.igaworks.util.bolts_task.Task.delay(5000).continueWith(new com.igaworks.adbrix.impl.ADBrixFrameworkImpl.AdPopCornDailyPlayTimerTask.AnonymousClass1(r8));
         */
        /* JADX WARNING: Code restructure failed: missing block: B:29:0x00af, code lost:
            com.igaworks.core.IgawLogger.Logging(com.igaworks.adbrix.impl.ADBrixFrameworkImpl.getContext(), com.igaworks.core.IgawConstant.QA_TAG, "DailyPlay ReEngaement: Organic User", 3, true);
            com.igaworks.adbrix.impl.ADBrixFrameworkImpl.onProcessDailyPlay = false;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:31:0x00c7, code lost:
            if (com.igaworks.adbrix.impl.ADBrixFrameworkImpl.getContext() == null) goto L_0x00e3;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:32:0x00c9, code lost:
            com.igaworks.core.IgawLogger.Logging(com.igaworks.adbrix.impl.ADBrixFrameworkImpl.getContext(), com.igaworks.core.IgawConstant.QA_TAG, "DailyPlay ReEngaement: Null ", 3, true);
            com.igaworks.adbrix.db.DailyPlayDAO.getInstance().saveLastConversionDateTime(com.igaworks.adbrix.impl.ADBrixFrameworkImpl.getContext());
         */
        /* JADX WARNING: Code restructure failed: missing block: B:33:0x00e3, code lost:
            com.igaworks.adbrix.impl.ADBrixFrameworkImpl.onProcessDailyPlay = false;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:41:?, code lost:
            return;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:42:?, code lost:
            return;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:44:?, code lost:
            return;
         */
        public void run() {
            try {
                if (ADBrixHttpManager.schedule == null || RequestParameter.getATRequestParameter(ADBrixFrameworkImpl.getContext()).getReferralKey() <= -1) {
                    ADBrixFrameworkImpl.retryTime = ADBrixFrameworkImpl.retryTime + 1;
                    if (ADBrixFrameworkImpl.retryTime < 5) {
                        ADBrixFrameworkImpl.this.startDailyPlayCheckTask();
                        return;
                    }
                    return;
                }
                ADBrixFrameworkImpl.retryTime = 0;
                synchronized (ADBrixFrameworkImpl.lockObj) {
                    if (!ADBrixFrameworkImpl.onProcessDailyPlay) {
                        ADBrixFrameworkImpl.onProcessDailyPlay = true;
                    }
                }
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "DailyPlayTimerTask Error: " + e.getMessage());
            }
        }
    }

    protected ADBrixFrameworkImpl() {
    }

    public ADBrixHttpManager getHttpManager(Context context) {
        initAppInfo(context);
        if (this.httpManager == null) {
            this.httpManager = ADBrixHttpManager.getManager(context);
        }
        return this.httpManager;
    }

    public void firstTimeExperience(String name) {
        activity("fte", name, null, null, appContext);
    }

    public void firstTimeExperience(String name, String param) {
        activity("fte", name, param, null, appContext);
    }

    public void retention(String name) {
        activity("ret", name, null, null, appContext);
    }

    public void retention(String name, String param) {
        activity("ret", name, param, null, appContext);
    }

    public void showAD(String name, Activity activity) {
        PromotionHandler.dialogOpenner = activity;
        PromotionHandler.onPlayBtnClickListener = null;
        PromotionHandler.promotionActionListener = null;
        activity(CommonInterface.AD_SPACE_GROUP, name, null, null, appContext);
    }

    public void showAD(String name, Activity activity, ADBrixCallbackListener onPlayBtnClickListener) {
        PromotionHandler.dialogOpenner = activity;
        PromotionHandler.onPlayBtnClickListener = onPlayBtnClickListener;
        PromotionHandler.promotionActionListener = null;
        activity(CommonInterface.AD_SPACE_GROUP, name, null, null, appContext);
    }

    public void showAD(String name, Activity activity, PromotionActionListener promotionActionListener) {
        PromotionHandler.dialogOpenner = activity;
        PromotionHandler.onPlayBtnClickListener = null;
        PromotionHandler.promotionActionListener = promotionActionListener;
        activity(CommonInterface.AD_SPACE_GROUP, name, null, null, appContext);
    }

    public void hideAD() {
        PromotionHandler.onPlayBtnClickListener = null;
        PromotionHandler.promotionActionListener = null;
        PromotionHandler.closePromotion();
    }

    public void buy(String name) {
        activity("buy", name, null, null, appContext);
    }

    public void buy(String name, String param) {
        activity("buy", name, param, null, appContext);
    }

    public void setCustomCohort(final CohortVariable cohortVariable, final String cohort) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    IgawLogger.Logging(ADBrixFrameworkImpl.appContext, IgawConstant.QA_TAG, "setCustomCohort : " + cohortVariable.toString() + "/" + cohort, 3, false);
                    CohortDAO.updateCohort(ADBrixFrameworkImpl.appContext, cohortVariable.toString(), cohort);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    public void setDemographic(String key, String value) {
        save_demographic(key, value);
    }

    public void onActivityCalled(Context context, String group, String activityName, RequestParameter parameter) {
        IgawLogger.Logging(context, IgawConstant.QA_TAG, String.format("onActivityCalled > group - %s, activity - %s", new Object[]{group, activityName}), 3);
        CPECompletionHandler.checkAndComplete(context, group, activityName, parameter, ADBrixHttpManager.getManager(context), null);
    }

    public void onStartSession(final Context context, final RequestParameter parameter, final boolean sessionContinue) {
        synchronized (lockObj) {
            DL_SESSION_START_TIME = SystemClock.elapsedRealtime();
        }
        Task.forResult(null).continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Object, Task<Void>>() {
            public Task<Void> then(Task<Object> task) throws Exception {
                String lastOnSessionDateTime = DailyPlayDAO.getInstance().getLastOnStartSessionDateTime(context);
                try {
                    if (!lastOnSessionDateTime.equals("")) {
                        DailyPlayDAO.getInstance().setLastOnStartSessionDateTime(context);
                        Calendar lastOnSessionDateTimeCal = Calendar.getInstance();
                        Calendar now = Calendar.getInstance();
                        lastOnSessionDateTimeCal.setTime(DailyPlayDAO.sdf.parse(lastOnSessionDateTime));
                        if (now.get(5) != lastOnSessionDateTimeCal.get(5)) {
                            ADBrixFrameworkImpl.DL_PLAY_TIME_PASS = 0;
                        }
                    }
                } catch (Exception e) {
                    Log.e(IgawConstant.QA_TAG, "Check startSessionDateTime Error: " + e.getMessage());
                    ADBrixFrameworkImpl.DL_PLAY_TIME_PASS = 0;
                }
                ADBrixHttpManager httpManager = ADBrixFrameworkImpl.this.getHttpManager(context);
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "adbrix onStartSession called", 3);
                if (!(context instanceof Activity)) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "context is not instance of Activity", 1);
                } else if (PromotionHandler.dialogOpenner != null) {
                    PromotionHandler.dialogOpenner = (Activity) context;
                }
                if (!sessionContinue || ADBrixHttpManager.schedule == null) {
                    httpManager.getScheduleForADBrix(parameter, context, DeviceIDManger.getInstance(context).getAESPuid(context), ScheduleDAO.getInstance().getSchedule(context));
                }
                if (ADBrixHttpManager.schedule != null) {
                    ADBrixFrameworkImpl.this.retryCPEConversion(context);
                    if (RequestParameter.getATRequestParameter(context).getReferralKey() > 0) {
                        Log.d(IgawConstant.QA_TAG, "DailyPlay start and check");
                        ADBrixFrameworkImpl.this.DailyPlayStart(context);
                    }
                } else {
                    ADBrixFrameworkImpl.this.setGetScheduleEventListener();
                }
                if (!sessionContinue) {
                    CPESessionImpressionDAO.getInstance().clearImpressionData(context);
                    PromotionHandler.nextCampaigns.clear();
                }
                return null;
            }
        }, (Executor) InternalAction.NETWORK_EXECUTOR);
    }

    public void addConversionCache(final Context context, final RequestParameter rp, final String result) {
        Task.delay(1000).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Void, Void>() {
            public Void then(Task<Void> task) throws Exception {
                if (ADBrixHttpManager.schedule != null) {
                    JSONObject jsonObject = new JSONObject(result);
                    if (jsonObject.getBoolean(HttpManager.RESULT) && !jsonObject.isNull(HttpManager.DATA)) {
                        JSONArray conversionArray = new JSONArray(new JSONObject(jsonObject.getString(HttpManager.DATA)).getString(HttpManager.CONVERSION_KEY_LIST));
                        for (int i = 0; i < conversionArray.length(); i++) {
                            int key = conversionArray.getInt(i);
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "onReferralResponse - addConversionCache > key : " + key, 3, false);
                            if (key != -1 && (rp.getConversionCache() == null || !rp.getConversionCache().contains(Integer.valueOf(key)))) {
                                List<Engagement> engagements = ADBrixHttpManager.schedule.getSchedule().getEngagements();
                                for (int j = 0; j < engagements.size(); j++) {
                                    Engagement engagement = engagements.get(j);
                                    if (engagement.getConversionKey() == key) {
                                        String msg = engagement.getDisplayData().getCompleteMessage();
                                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "callback complete cpe by referral > msg : " + msg + ", duration : " + engagement.getDisplayData().getCompleteToastMSec(), 3);
                                        if (engagement.getDisplayData().getCompleteToastMSec() > 0 && msg != null && msg.length() > 0 && !msg.equals("null")) {
                                            ADBrixHttpManager.getManager(context).makeCompleteToast(context, (long) engagement.getDisplayData().getCompleteToastMSec(), msg);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return null;
            }
        }, (Executor) InternalAction.NETWORK_EXECUTOR);
    }

    public void restoreCPEAction_onGetReferralResponse(Context context, RequestParameter rp) {
        if (ADBrixHttpManager.schedule != null) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "onReferralResponse - restoreCPEAction", 3);
            CPECompletionHandler.restoreCPEAction(context, rp, ADBrixHttpManager.getManager(context));
            return;
        }
        Log.i(IgawConstant.QA_TAG, "Adbrix SDK waiting for schedule...");
    }

    public void restoreCPEAction_OnGetSchedule(Context context, RequestParameter rp) {
        if (rp.getADBrixUserNo() > 0) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "OnGetSchedule - restoreCPEAction", 3);
            CPECompletionHandler.restoreCPEAction(context, rp, ADBrixHttpManager.getManager(context));
            return;
        }
        Log.i(IgawConstant.QA_TAG, "Adbrix SDK waiting for referrer...");
    }

    public void onGetReferralResponse(Context context, String result) {
        try {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "onReferralResponse called.", 3);
            RequestParameter rp = RequestParameter.getATRequestParameter(context);
            restoreCPEAction_onGetReferralResponse(context, rp);
            addConversionCache(context, rp, result);
            Task.delay(2000).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Void, Void>() {
                public Void then(Task<Void> task) throws Exception {
                    if (ADBrixHttpManager.schedule == null) {
                        Log.d(IgawConstant.QA_TAG, "DailyPlay is waiting schedule");
                    } else if (RequestParameter.getATRequestParameter(ADBrixFrameworkImpl.getContext()).getReferralKey() == 0) {
                        Log.d(IgawConstant.QA_TAG, "DailyPlay Skip: Organic");
                    } else {
                        Log.d(IgawConstant.QA_TAG, "DailyPlay start and check");
                        ADBrixFrameworkImpl.this.DailyPlayStart(ADBrixFrameworkImpl.getContext());
                    }
                    return null;
                }
            }, (Executor) Task.BACKGROUND_EXECUTOR);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void useCoupon(String coupon) {
        activity(ADBrixInterface.COUPON_GROUP, "gameshuttle", coupon, null, appContext);
    }

    public void purchase(Context context, String orderID, String productID, String productName, double price, int quantity, Currency currency, String category) {
        try {
            IgawCommerce.purchase(context, orderID, productID, productName, price, quantity, currency, category);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void purchase(Context context, List<IgawCommerceItemModel> purchaseList) {
        try {
            IgawCommerce.purchase(context, purchaseList);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void purchase(Context context, String purchaseDataJsonString) {
        try {
            IgawCommerce.purchase(context, purchaseDataJsonString);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void onEndSession(Context context, int sessionStackCount) {
        IgawLogger.Logging(context, IgawConstant.QA_TAG, "adbrix onEndSession called", 3, true);
        synchronized (lockObj) {
            if (DL_SESSION_START_TIME > 0) {
                DL_PLAY_TIME_PASS = (int) ((SystemClock.elapsedRealtime() - DL_SESSION_START_TIME) + ((long) DL_PLAY_TIME_PASS));
                DL_SESSION_START_TIME = 0;
            } else {
                Log.e(IgawConstant.QA_TAG, "StartSession and EndSession are pair. Must call startSession before endSession");
                DL_PLAY_TIME_PASS = 0;
            }
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "DailyPlay >> elapsed: " + DL_PLAY_TIME_PASS + " ms", 3, false);
            if (this.timer != null) {
                this.timer.cancel();
                this.timer = null;
            }
        }
    }

    /* access modifiers changed from: private */
    public void DailyPlayStart(Context context) {
        if (DailyPlayDAO.getInstance().canJoinCampaignToday(getContext())) {
            startDailyPlayCheckTask();
        }
    }

    /* access modifiers changed from: private */
    public void startDailyPlayCheckTask() {
        try {
            synchronized (lockObj) {
                if (this.timer != null) {
                    IgawLogger.Logging(getContext(), IgawConstant.QA_TAG, "Start DailyPlay Timer again.", 2, true);
                    this.timer.cancel();
                }
                this.timer = new Timer();
                this.dailyPlayCheckTask = new AdPopCornDailyPlayTimerTask();
            }
            int REQUIRED_PLAY_TIME = DailyPlayDAO.getInstance().getPlayTime(getContext());
            IgawLogger.Logging(getContext(), IgawConstant.QA_TAG, "startDailyPlayCheckTask ... REQUIRED_PLAY_TIME: " + REQUIRED_PLAY_TIME + ">> Elapsed: " + DL_PLAY_TIME_PASS, 2, true);
            int waitTime = REQUIRED_PLAY_TIME - DL_PLAY_TIME_PASS;
            if (waitTime > 1000) {
                this.timer.schedule(this.dailyPlayCheckTask, (long) waitTime);
            } else {
                this.timer.schedule(this.dailyPlayCheckTask, 1000);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /* access modifiers changed from: private */
    public void retryCPEConversion(final Context context) {
        if (CommonHelper.checkInternetConnection(context)) {
            final Capture<ArrayList<TrackingActivityModel>> activityParam = new Capture<>(null);
            ConversionDAOForRetryCompletion retryDao = ConversionDAOForRetryCompletion.getDAO(context);
            List<RetryCompleteConversion> retryConversions = retryDao.getRetryConversions();
            if (retryConversions != null && retryConversions.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "cpe complete retry start, the num of conversion = " + retryConversions.size(), 3);
                final ArrayList<Integer> retryConversionKeys = new ArrayList<>();
                for (RetryCompleteConversion retryConversion : retryConversions) {
                    if (retryConversion.getRetryCount() >= 3) {
                        retryDao.removeRetryCount(retryConversion.getConversionKey());
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "cpe complete retry failed 3 times, conversionKey = " + retryConversion.getConversionKey(), 3);
                    } else {
                        retryConversionKeys.add(Integer.valueOf(retryConversion.getConversionKey()));
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "cpe complete retry, conversionKey = " + retryConversion.getConversionKey(), 3);
                    }
                }
                Task.forResult(null).onSuccessTask(new Continuation<Void, Task<ArrayList<TrackingActivityModel>>>() {
                    public Task<ArrayList<TrackingActivityModel>> then(Task<Void> task) throws Exception {
                        return TrackingActivitySQLiteDB.getInstance(ADBrixFrameworkImpl.getContext()).getActivityListParam(false, ADBrixFrameworkImpl.getContext(), SettingsJsonConstants.SESSION_KEY, "start", ADBrixFrameworkImpl.endSessionParam);
                    }
                }).onSuccessTask(new Continuation<ArrayList<TrackingActivityModel>, Task<ArrayList<TrackingActivityModel>>>() {
                    public Task<ArrayList<TrackingActivityModel>> then(Task<ArrayList<TrackingActivityModel>> task) throws Exception {
                        activityParam.set((ArrayList) task.getResult());
                        return TrackingActivitySQLiteDB.getInstance(context).getImpressionData(false, context);
                    }
                }).onSuccess((Continuation<TResult, TContinuationResult>) new Continuation<ArrayList<TrackingActivityModel>, Void>() {
                    public Void then(Task<ArrayList<TrackingActivityModel>> task) throws Exception {
                        ADBrixFrameworkImpl.this.httpManager.completeCPECallForADBrix(ADBrixFrameworkImpl.parameter, context, (ArrayList) activityParam.get(), (ArrayList) task.getResult(), retryConversionKeys);
                        return null;
                    }
                }, (Executor) InternalAction.NETWORK_EXECUTOR);
            }
        }
    }

    /* access modifiers changed from: private */
    public void setGetScheduleEventListener() {
        ADBrixHttpManager.onGetScheduleEvent = new OnGetSchedule() {
            public void onGetSchedule(Context context, boolean result) {
                if (result) {
                    RequestParameter rp = RequestParameter.getATRequestParameter(context);
                    ADBrixFrameworkImpl.this.restoreCPEAction_OnGetSchedule(context, rp);
                    ADBrixFrameworkImpl.this.retryCPEConversion(context);
                    long ref = rp.getReferralKey();
                    if (ref == -1) {
                        Log.d(IgawConstant.QA_TAG, "DailyPlay is waiting getReferrer");
                    }
                    if (ref == 0) {
                        Log.d(IgawConstant.QA_TAG, "DailyPlay Skip >> Organic");
                    }
                    if (ref > 0) {
                        Log.d(IgawConstant.QA_TAG, "DailyPlay start and check");
                        ADBrixFrameworkImpl.this.DailyPlayStart(context);
                    }
                }
            }
        };
    }

    public void purchase(Context context, String productID, Double price, Currency currency, IgawPaymentMethod paymentMethod) {
        try {
            IgawCommerce.purchase(context, productID, price, currency, paymentMethod);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void purchase(Context context, String orderID, IgawCommerceProductModel purchaseDetail, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod) {
        try {
            IgawCommerce.purchase(context, orderID, purchaseDetail, discount, deliveryCharge, paymentMethod);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void purchaseBulk(Context context, String orderID, List<IgawCommerceProductModel> purchaseList, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod) {
        try {
            IgawCommerce.purchase(context, orderID, purchaseList, discount, deliveryCharge, paymentMethod);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void appOpen(Context context) {
        try {
            IgawCommerce.appOpen(context);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void deeplinkOpen(Context context, String deeplinkUrl) {
        try {
            IgawCommerce.deeplinkOpen(context, deeplinkUrl);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void productView(Context context, IgawCommerceProductModel product) {
        try {
            IgawCommerce.productView(context, product);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void refund(Context context, String orderId, IgawCommerceProductModel product, Double penaltyCharge) {
        try {
            IgawCommerce.refund(context, orderId, product, penaltyCharge);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void refundBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double penaltyCharge) {
        try {
            IgawCommerce.refundBulk(context, orderId, products, penaltyCharge);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void addToCart(Context context, IgawCommerceProductModel product) {
        try {
            IgawCommerce.addToCart(context, product);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void addToCartBulk(Context context, List<IgawCommerceProductModel> products) {
        try {
            IgawCommerce.addToCartBulk(context, products);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void login(Context context, String usn) {
        IgawCommon.setUserId(context, usn);
        try {
            IgawCommerce.login(context);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void addToWishList(Context context, IgawCommerceProductModel product) {
        try {
            IgawCommerce.addToWishList(context, product);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void categoryView(Context context, IgawCommerceProductCategoryModel category) {
        try {
            IgawCommerce.categoryView(context, category);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void categoryView(Context context, IgawCommerceProductCategoryModel category, List<IgawCommerceProductModel> products) {
        try {
            IgawCommerce.categoryView(context, category, products);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void reviewOrder(Context context, String orderId, IgawCommerceProductModel product, Double discount, Double deliveryCharge) {
        try {
            IgawCommerce.reviewOrder(context, orderId, product, discount, deliveryCharge);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void reviewOrderBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, Double deliveryCharge) {
        try {
            IgawCommerce.reviewOrderBulk(context, orderId, products, discount, deliveryCharge);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void paymentView(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, Double deliveryCharge) {
        try {
            IgawCommerce.paymentView(context, orderId, products, discount, deliveryCharge);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void search(Context context, String keyword, List<IgawCommerceProductModel> resultProducts) {
        try {
            IgawCommerce.search(context, keyword, resultProducts);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void share(Context context, IgawSharingChannel sharingChennel, IgawCommerceProductModel product) {
        try {
            IgawCommerce.share(context, sharingChennel, product);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void purchase(Context context, String productID, Double price, Currency currency, IgawPaymentMethod paymentMethod, Map<String, String> attrData) {
        try {
            IgawCommerce.purchase(context, productID, price, currency, paymentMethod, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void purchase(Context context, String orderID, IgawCommerceProductModel purchaseDetail, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod, Map<String, String> attrData) {
        try {
            IgawCommerce.purchase(context, orderID, purchaseDetail, discount, deliveryCharge, paymentMethod, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void purchaseBulk(Context context, String orderID, List<IgawCommerceProductModel> purchaseList, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod, Map<String, String> attrData) {
        try {
            IgawCommerce.purchase(context, orderID, purchaseList, discount, deliveryCharge, paymentMethod, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void appOpen(Context context, Map<String, String> attrData) {
        try {
            IgawCommerce.appOpen(context, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void deeplinkOpen(Context context, String deeplinkUrl, Map<String, String> attrData) {
        try {
            IgawCommerce.deeplinkOpen(context, deeplinkUrl, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void productView(Context context, IgawCommerceProductModel product, Map<String, String> attrData) {
        try {
            IgawCommerce.productView(context, product, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void refund(Context context, String orderId, IgawCommerceProductModel product, Double penaltyCharge, Map<String, String> attrData) {
        try {
            IgawCommerce.refund(context, orderId, product, penaltyCharge, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void refundBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double penaltyCharge, Map<String, String> attrData) {
        try {
            IgawCommerce.refundBulk(context, orderId, products, penaltyCharge, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void addToCart(Context context, IgawCommerceProductModel product, Map<String, String> attrData) {
        try {
            IgawCommerce.addToCart(context, product, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void addToCartBulk(Context context, List<IgawCommerceProductModel> products, Map<String, String> attrData) {
        try {
            IgawCommerce.addToCartBulk(context, products, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void login(Context context, String usn, Map<String, String> attrData) {
        IgawCommon.setUserId(context, usn);
        try {
            IgawCommerce.login(context, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void addToWishList(Context context, IgawCommerceProductModel product, Map<String, String> attrData) {
        try {
            IgawCommerce.addToWishList(context, product, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void categoryView(Context context, IgawCommerceProductCategoryModel category, Map<String, String> attrData) {
        try {
            IgawCommerce.categoryView(context, category, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void categoryView(Context context, IgawCommerceProductCategoryModel category, List<IgawCommerceProductModel> products, Map<String, String> attrData) {
        try {
            IgawCommerce.categoryView(context, category, products, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void reviewOrder(Context context, String orderId, IgawCommerceProductModel product, Double discount, Double deliveryCharge, Map<String, String> attrData) {
        try {
            IgawCommerce.reviewOrder(context, orderId, product, discount, deliveryCharge, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void reviewOrderBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, Double deliveryCharge, Map<String, String> attrData) {
        try {
            IgawCommerce.reviewOrderBulk(context, orderId, products, discount, deliveryCharge, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void paymentView(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, Double deliveryCharge, Map<String, String> attrData) {
        try {
            IgawCommerce.paymentView(context, orderId, products, discount, deliveryCharge, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void search(Context context, String keyword, List<IgawCommerceProductModel> resultProducts, Map<String, String> attrData) {
        try {
            IgawCommerce.search(context, keyword, resultProducts, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void share(Context context, IgawSharingChannel sharingChennel, IgawCommerceProductModel product, Map<String, String> attrData) {
        try {
            IgawCommerce.share(context, sharingChennel, product, attrData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}