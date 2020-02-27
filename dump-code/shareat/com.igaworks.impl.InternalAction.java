package com.igaworks.impl;

import android.content.Context;
import android.os.Build.VERSION;
import android.util.Log;
import com.igaworks.IgawCommon;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;
import com.igaworks.dao.AppImpressionDAO;
import com.igaworks.dao.ReferralInfoDAO;
import com.igaworks.dao.tracking.TrackingActivityModel;
import com.igaworks.dao.tracking.TrackingActivitySQLiteDB;
import com.igaworks.dao.tracking.TrackingActivitySQLiteOpenHelper;
import com.igaworks.net.CommonHttpManager;
import com.igaworks.util.CommonHelper;
import com.igaworks.util.bolts_task.Capture;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.Task;
import java.util.ArrayList;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class InternalAction {
    private static final int CORE_POOL_SIZE = ((CPU_COUNT * 2) + 1);
    private static final int CPU_COUNT = Runtime.getRuntime().availableProcessors();
    private static final long KEEP_ALIVE_TIME = 1;
    private static final int MAX_POOL_SIZE = (((CPU_COUNT * 2) * 2) + 1);
    private static final int MAX_QUEUE_SIZE = 128;
    public static final ExecutorService NETWORK_EXECUTOR = newThreadPoolExecutor(CORE_POOL_SIZE, MAX_POOL_SIZE, 1, TimeUnit.SECONDS, new LinkedBlockingQueue(), sThreadFactory);
    private static final ThreadFactory sThreadFactory = new ThreadFactory() {
        private final AtomicInteger mCount = new AtomicInteger(1);

        public Thread newThread(Runnable r) {
            return new Thread(r, "Igaworks.NETWORK_EXECUTOR-thread-" + this.mCount.getAndIncrement());
        }
    };
    private static InternalAction singleton;

    private InternalAction() {
    }

    public static InternalAction getInstance() {
        if (singleton == null) {
            synchronized (InternalAction.class) {
                try {
                    if (singleton == null) {
                        singleton = new InternalAction();
                    }
                }
            }
        }
        return singleton;
    }

    private static ThreadPoolExecutor newThreadPoolExecutor(int corePoolSize, int maxPoolSize, long keepAliveTime, TimeUnit timeUnit, BlockingQueue<Runnable> workQueue, ThreadFactory threadFactory) {
        ThreadPoolExecutor executor = new ThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit, workQueue, threadFactory);
        if (VERSION.SDK_INT >= 9) {
            executor.allowCoreThreadTimeOut(true);
        }
        return executor;
    }

    public void sendOphanActivities(final Context context, boolean isTest, CommonHttpManager httpManager) {
        if (CommonHelper.checkInternetConnection(context) || isTest) {
            final Capture<ArrayList<TrackingActivityModel>> activityParam = new Capture<>(null);
            final boolean z = isTest;
            final Context context2 = context;
            final CommonHttpManager commonHttpManager = httpManager;
            Task.forResult(null).onSuccessTask(new Continuation<Void, Task<ArrayList<TrackingActivityModel>>>() {
                public Task<ArrayList<TrackingActivityModel>> then(Task<Void> task) throws Exception {
                    return TrackingActivitySQLiteDB.getInstance(context).getOrphanTracking(context, TrackingActivitySQLiteOpenHelper.TABLE_APP_TRACKING);
                }
            }).onSuccessTask(new Continuation<ArrayList<TrackingActivityModel>, Task<ArrayList<TrackingActivityModel>>>() {
                public Task<ArrayList<TrackingActivityModel>> then(Task<ArrayList<TrackingActivityModel>> task) throws Exception {
                    activityParam.set((ArrayList) task.getResult());
                    return TrackingActivitySQLiteDB.getInstance(context).getOrphanTracking(context, TrackingActivitySQLiteOpenHelper.TABLE_IMPRESSION_TRACKING);
                }
            }).onSuccess((Continuation<TResult, TContinuationResult>) new Continuation<ArrayList<TrackingActivityModel>, Void>() {
                public Void then(Task<ArrayList<TrackingActivityModel>> task) throws Exception {
                    ArrayList<TrackingActivityModel> impressionParam = (ArrayList) task.getResult();
                    if (z) {
                        Log.i(IgawConstant.QA_TAG, "sendOphanActivities");
                    }
                    try {
                        if ((activityParam.get() != null && ((ArrayList) activityParam.get()).size() > 0) || (impressionParam != null && impressionParam.size() > 0)) {
                            Context context = context2;
                            Object[] objArr = new Object[2];
                            objArr[0] = Integer.valueOf(activityParam.get() == null ? 0 : ((ArrayList) activityParam.get()).size());
                            objArr[1] = Integer.valueOf(impressionParam == null ? 0 : impressionParam.size());
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, String.format("Send orphan tracking data to Adbrix data - activity : %d, imp : %d", objArr), 2, true);
                            commonHttpManager.trackingForADBrix(RequestParameter.getATRequestParameter(context2), context2, (ArrayList) activityParam.get(), impressionParam);
                        }
                    } catch (Exception ex) {
                        Log.e(IgawConstant.QA_TAG, "OnStartApplication: Send orphan tracking data to Adbrix >> Error >>" + ex.getMessage());
                    }
                    return null;
                }
            }, (Executor) NETWORK_EXECUTOR);
        }
    }

    public void referrerCallForAdbrix(Context context, boolean isTest, RequestParameter parameter, CommonHttpManager httpManager) {
        if (CommonHelper.checkInternetConnection(context) || isTest) {
            final boolean z = isTest;
            final Context context2 = context;
            final RequestParameter requestParameter = parameter;
            final CommonHttpManager commonHttpManager = httpManager;
            Task.delay(500).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Void, Void>() {
                public Void then(Task<Void> task) throws Exception {
                    if (z) {
                        Log.i(IgawConstant.QA_TAG, "referrerCallForAdbrix");
                    }
                    if (ReferralInfoDAO.getOnReceiveReferralFlag(context2)) {
                        if (!AppImpressionDAO.getSharedPreferencesForFirstStart(context2).contains("fts") || requestParameter.getReferralKey() == -1) {
                            AppImpressionDAO.addFirstStartToSP(context2);
                        }
                        if (ReferralInfoDAO.isSentRefferrerSuccess2Adbrix(context2)) {
                            Log.i(IgawConstant.QA_TAG, "Can not send CPI referrerCallForAdbrix multiple times");
                            ReferralInfoDAO.clearOnReceiveReferralFlag(context2);
                        } else {
                            IgawLogger.Logging(context2, IgawConstant.QA_TAG, "ReferralInfoDAO >> onReceiveReferral: true! SDK will call onReceiveReferral() api", 3, false);
                            IgawCommon.onReceiveReferral(context2, ReferralInfoDAO.getReferralInfo_referrer_params(context2));
                        }
                    } else {
                        boolean isAdbrixSyn = AppImpressionDAO.getSynAdbrix(CommonFrameworkImpl.getContext());
                        if ((!AppImpressionDAO.getSharedPreferencesForFirstStart(context2).contains("fts") || requestParameter.getReferralKey() == -1 || !isAdbrixSyn) && (requestParameter.getReferralKey() == -1 || requestParameter.getADBrixUserNo() < 1 || !isAdbrixSyn)) {
                            AppImpressionDAO.addFirstStartToSP(context2);
                            commonHttpManager.normal_referrerCallForADBrix(requestParameter, context2, null);
                        }
                    }
                    return null;
                }
            }, (Executor) NETWORK_EXECUTOR);
        }
    }

    public void trackingForAdbrixCall(final Context context, boolean isTest, CommonHttpManager httpManager, String group, String act, long endSessionParam) {
        final Capture<ArrayList<TrackingActivityModel>> activityParam = new Capture<>(null);
        final Context context2 = context;
        final String str = group;
        final String str2 = act;
        final long j = endSessionParam;
        final boolean z = isTest;
        final String str3 = act;
        final Capture capture = activityParam;
        final Context context3 = context;
        final CommonHttpManager commonHttpManager = httpManager;
        Task.forResult(null).onSuccessTask(new Continuation<Void, Task<ArrayList<TrackingActivityModel>>>() {
            public Task<ArrayList<TrackingActivityModel>> then(Task<Void> task) throws Exception {
                return TrackingActivitySQLiteDB.getInstance(context2).getActivityListParam(false, context2, str, str2, j);
            }
        }).onSuccessTask(new Continuation<ArrayList<TrackingActivityModel>, Task<ArrayList<TrackingActivityModel>>>() {
            public Task<ArrayList<TrackingActivityModel>> then(Task<ArrayList<TrackingActivityModel>> task) throws Exception {
                activityParam.set((ArrayList) task.getResult());
                return TrackingActivitySQLiteDB.getInstance(context).getImpressionData(false, context);
            }
        }).onSuccess((Continuation<TResult, TContinuationResult>) new Continuation<ArrayList<TrackingActivityModel>, Void>() {
            public Void then(Task<ArrayList<TrackingActivityModel>> task) throws Exception {
                String TAG;
                ArrayList<TrackingActivityModel> impressionParam = (ArrayList) task.getResult();
                if (z) {
                    Log.i(IgawConstant.QA_TAG, "trackingForAdbrixCall");
                }
                if (str3.equals("start")) {
                    TAG = "OnStartSession";
                } else if (str3.equals("end")) {
                    TAG = "OnEndSession";
                } else {
                    TAG = "Flush tracking data";
                }
                try {
                    if ((capture.get() != null && ((ArrayList) capture.get()).size() > 0) || (impressionParam != null && impressionParam.size() > 0)) {
                        Context context = context3;
                        String sb = new StringBuilder(String.valueOf(TAG)).append(": trackingForAdbrix data - activity : %d, imp : %d").toString();
                        Object[] objArr = new Object[2];
                        objArr[0] = Integer.valueOf(capture.get() == null ? 0 : ((ArrayList) capture.get()).size());
                        objArr[1] = Integer.valueOf(impressionParam == null ? 0 : impressionParam.size());
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, String.format(sb, objArr), 2, true);
                        commonHttpManager.trackingForADBrix(RequestParameter.getATRequestParameter(context3), context3, (ArrayList) capture.get(), impressionParam);
                    }
                } catch (Exception ex) {
                    Log.e(IgawConstant.QA_TAG, new StringBuilder(String.valueOf(TAG)).append(": trackingForAdbrix Error >>").append(ex.getMessage()).toString());
                }
                return null;
            }
        }, (Executor) NETWORK_EXECUTOR);
    }
}