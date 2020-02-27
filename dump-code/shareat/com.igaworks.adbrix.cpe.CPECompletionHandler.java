package com.igaworks.adbrix.cpe;

import android.content.Context;
import com.igaworks.adbrix.core.ADBrixHttpManager;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;
import com.igaworks.dao.ActivityDAOForRestore;
import com.igaworks.impl.InternalAction;
import com.igaworks.interfaces.CommonInterface;
import com.igaworks.model.RestoreActivity;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.Task;
import com.igaworks.util.image.ImageDownloader;
import io.fabric.sdk.android.services.common.CommonUtils;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.concurrent.Executor;

public class CPECompletionHandler {
    public static final String TAG = "CPECompletionHandler";
    private static ImageDownloader imageDownloader;
    /* access modifiers changed from: private */
    public static boolean onRestore = false;

    public static ImageDownloader getImageDownloader(Context context) {
        if (imageDownloader == null) {
            imageDownloader = new ImageDownloader(context, "imagecache");
        }
        return imageDownloader;
    }

    public static void checkAndComplete(Context context, String group, String activityName, RequestParameter parameter, ADBrixHttpManager httpManager, Calendar restoreTime) {
        final Context context2 = context;
        final RequestParameter requestParameter = parameter;
        final String str = group;
        final String str2 = activityName;
        final ADBrixHttpManager aDBrixHttpManager = httpManager;
        final Calendar calendar = restoreTime;
        Task.forResult(null).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Void, Void>() {
            public Void then(Task<Void> task) throws Exception {
                boolean z = true;
                try {
                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, "ADBrixManager > Schedule check start : is schedule exist = " + (ADBrixHttpManager.schedule != null), 3, false);
                    if (ADBrixHttpManager.schedule == null || requestParameter.getReferralKey() < 0) {
                        Context context = context2;
                        StringBuilder sb = new StringBuilder("ADBrixManager > add restore activity >> schedule == null : ");
                        if (ADBrixHttpManager.schedule != null) {
                            z = false;
                        }
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, sb.append(z).append(", parameter.getReferralKey : ").append(requestParameter.getReferralKey()).toString(), 3, true);
                        ActivityDAOForRestore.getDAO(context2).addItem(str, str2);
                        return null;
                    }
                    EngagementCompletionHandler.checkAndCompleteEngagement(context2, str, str2, requestParameter, aDBrixHttpManager, calendar);
                    if (str.equals(CommonInterface.AD_SPACE_GROUP)) {
                        PromotionHandler.checkAvailablePromotion(context2, str2, requestParameter);
                    }
                    return null;
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, (Executor) InternalAction.NETWORK_EXECUTOR);
    }

    public static void restoreCPEAction(final Context context, final RequestParameter parameter, final ADBrixHttpManager tracer) {
        if (!onRestore) {
            onRestore = true;
            Task.forResult(null).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Void, Void>() {
                public Void then(Task<Void> task) throws Exception {
                    try {
                        ActivityDAOForRestore activityDAOForRestore = ActivityDAOForRestore.getDAO(context);
                        List<RestoreActivity> restoreActivities = activityDAOForRestore.getRestoreActivities();
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "clearRestoreActivity result : " + activityDAOForRestore.clearRestoreActivity(), 3);
                        List<String> restoredSpace = null;
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "restoreCPEAction called", 3);
                        if (restoreActivities == null || restoreActivities.size() <= 0) {
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "there are no restore activity", 3);
                        } else {
                            if (restoreActivities.size() > 30) {
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "the number of restore activity over 30 : " + restoreActivities.size(), 3);
                                restoreActivities = restoreActivities.subList(0, 30);
                            }
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "the number of restore activity : " + restoreActivities.size(), 3);
                            for (RestoreActivity item : restoreActivities) {
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "restore item(group/activity) : " + item.getGroup() + "/" + item.getActivity(), 3);
                                EngagementCompletionHandler.checkAndCompleteEngagement(context, item.getGroup(), item.getActivity(), parameter, tracer, item.getRegistDatetime());
                                if (item.getGroup().equals(CommonInterface.AD_SPACE_GROUP)) {
                                    if (restoredSpace == null) {
                                        restoredSpace = new ArrayList<>();
                                    }
                                    if (!restoredSpace.contains(item.getActivity())) {
                                        restoredSpace.add(item.getActivity());
                                        PromotionHandler.checkAvailablePromotion(context, item.getActivity(), parameter);
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                    } finally {
                        CPECompletionHandler.onRestore = false;
                    }
                    return null;
                }
            }, (Executor) Task.BACKGROUND_EXECUTOR);
        }
    }

    public static String computeHashedName(String name) {
        try {
            MessageDigest digest = MessageDigest.getInstance(CommonUtils.MD5_INSTANCE);
            digest.update(name.getBytes());
            byte[] result = digest.digest();
            return String.format("%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", new Object[]{Byte.valueOf(result[0]), Byte.valueOf(result[1]), Byte.valueOf(result[2]), Byte.valueOf(result[3]), Byte.valueOf(result[4]), Byte.valueOf(result[5]), Byte.valueOf(result[6]), Byte.valueOf(result[7]), Byte.valueOf(result[8]), Byte.valueOf(result[9]), Byte.valueOf(result[10]), Byte.valueOf(result[11]), Byte.valueOf(result[12]), Byte.valueOf(result[13]), Byte.valueOf(result[14]), Byte.valueOf(result[15])});
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}