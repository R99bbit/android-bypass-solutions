package com.igaworks.adbrix.cpe;

import android.content.Context;
import android.util.Log;
import com.igaworks.adbrix.core.ADBrixHttpManager;
import com.igaworks.adbrix.db.DailyPlayDAO;
import com.igaworks.adbrix.model.DailyPlay;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;
import com.igaworks.dao.tracking.TrackingActivityModel;
import com.igaworks.dao.tracking.TrackingActivitySQLiteDB;
import com.igaworks.impl.InternalAction;
import com.igaworks.util.bolts_task.Capture;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.Task;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;

public class DailyPlayHandler {
    public static void checkandComplete(Context context, List<DailyPlay> dailyPlayStepList, int referrerKey) {
        int parentCK = DailyPlayDAO.getInstance().getLatestConversionKey(context);
        if (parentCK == -1) {
            int i = 0;
            while (i < dailyPlayStepList.size()) {
                DailyPlay dailyPlayStep = dailyPlayStepList.get(i);
                if (dailyPlayStep.getParentConversionKey() == referrerKey) {
                    int new_ConversionKey = dailyPlayStep.getConversionKey();
                    DailyPlayDAO.getInstance().setPlayTime(context, dailyPlayStep.getPlayTime());
                    ArrayList<Integer> conversionCacheList = RequestParameter.getATRequestParameter(context).getConversionCache();
                    if (conversionCacheList == null || !conversionCacheList.contains(Integer.valueOf(new_ConversionKey))) {
                        sendCompletRequest(context, new_ConversionKey);
                        return;
                    } else {
                        Log.i(IgawConstant.QA_TAG, "Conversion completed already: " + new_ConversionKey);
                        return;
                    }
                } else {
                    i++;
                }
            }
            return;
        }
        int i2 = 0;
        while (i2 < dailyPlayStepList.size()) {
            DailyPlay dailyPlayStep2 = dailyPlayStepList.get(i2);
            if (dailyPlayStep2.getParentConversionKey() == parentCK) {
                int new_ConversionKey2 = dailyPlayStep2.getConversionKey();
                DailyPlayDAO.getInstance().setPlayTime(context, dailyPlayStep2.getPlayTime());
                ArrayList<Integer> conversionCacheList2 = RequestParameter.getATRequestParameter(context).getConversionCache();
                if (conversionCacheList2 == null || !conversionCacheList2.contains(Integer.valueOf(new_ConversionKey2))) {
                    sendCompletRequest(context, new_ConversionKey2);
                    return;
                } else {
                    Log.i(IgawConstant.QA_TAG, "Conversion completed already: " + new_ConversionKey2);
                    return;
                }
            } else {
                i2++;
            }
        }
    }

    private static void sendCompletRequest(final Context context, int conversionkey) {
        DailyPlayDAO.getInstance().setPendingConversionKey(context, conversionkey);
        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > DailyPlayHandler sendCompleRequest", 3);
        final ArrayList<Integer> conversionList = new ArrayList<>();
        conversionList.add(Integer.valueOf(conversionkey));
        final Capture<ArrayList<TrackingActivityModel>> activityParam = new Capture<>(null);
        Task.forResult(null).onSuccessTask(new Continuation<Void, Task<ArrayList<TrackingActivityModel>>>() {
            public Task<ArrayList<TrackingActivityModel>> then(Task<Void> task) throws Exception {
                return TrackingActivitySQLiteDB.getInstance(context).getActivityListParam(false, context, "n/a", "n/a", 0);
            }
        }).onSuccessTask(new Continuation<ArrayList<TrackingActivityModel>, Task<ArrayList<TrackingActivityModel>>>() {
            public Task<ArrayList<TrackingActivityModel>> then(Task<ArrayList<TrackingActivityModel>> task) throws Exception {
                Capture.this.set((ArrayList) task.getResult());
                return TrackingActivitySQLiteDB.getInstance(context).getImpressionData(false, context);
            }
        }).onSuccess((Continuation<TResult, TContinuationResult>) new Continuation<ArrayList<TrackingActivityModel>, Void>() {
            public Void then(Task<ArrayList<TrackingActivityModel>> task) throws Exception {
                ADBrixHttpManager.getManager(context).completeCPECallForADBrix(RequestParameter.getATRequestParameter(context), context, (ArrayList) activityParam.get(), (ArrayList) task.getResult(), conversionList);
                return null;
            }
        }, (Executor) InternalAction.NETWORK_EXECUTOR);
    }
}