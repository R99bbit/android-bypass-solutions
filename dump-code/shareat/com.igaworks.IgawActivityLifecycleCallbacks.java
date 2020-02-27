package com.igaworks;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.ActivityManager.AppTask;
import android.app.ActivityManager.RunningTaskInfo;
import android.app.Application.ActivityLifecycleCallbacks;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Handler;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.impl.CommonFrameworkFactory;
import com.igaworks.impl.CommonFrameworkImpl;
import java.util.List;

public class IgawActivityLifecycleCallbacks implements ActivityLifecycleCallbacks {
    private final String ADPOPCORN_SETTING_SP = "adpopcorn_sdk_flag";
    private final String IAB_ACTIVITY_NAME = "IabV3Activity";
    private final String IS_ADPOPCORN_USER = "isAdPopcornUser";
    /* access modifiers changed from: private */
    public CommonFrameworkImpl commonInterface;

    public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
    }

    public void onActivityStarted(Activity activity) {
    }

    public void onActivityResumed(Activity activity) {
        IgawCommon.framework().startSession(activity);
    }

    public void onActivityPaused(final Activity activity) {
        IgawCommon.framework().endSession();
        try {
            boolean isAdPopcornUser = activity.getSharedPreferences("adpopcorn_sdk_flag", 0).getBoolean("isAdPopcornUser", false);
            IgawLogger.Logging(activity, IgawConstant.QA_TAG, "IgawActivityLifecycleCallbacks isAdPopcornUser : " + isAdPopcornUser, 1, true);
            if (isAdPopcornUser) {
                new Handler().postDelayed(new Runnable() {
                    public void run() {
                        try {
                            ActivityManager activityManager = (ActivityManager) activity.getApplicationContext().getSystemService("activity");
                            if (VERSION.SDK_INT >= 23) {
                                for (AppTask task : activityManager.getAppTasks()) {
                                    if (!(task == null || task.getTaskInfo() == null || task.getTaskInfo().topActivity == null)) {
                                        String topActivity = task.getTaskInfo().topActivity.toString();
                                        IgawLogger.Logging(activity, IgawConstant.QA_TAG, "IgawActivityLifecycleCallbacks onActivityPaused : " + topActivity, 1, true);
                                        if (topActivity != null && topActivity.contains("IabV3Activity")) {
                                            if (IgawActivityLifecycleCallbacks.this.commonInterface == null) {
                                                IgawActivityLifecycleCallbacks.this.commonInterface = (CommonFrameworkImpl) CommonFrameworkFactory.getCommonFramework();
                                            }
                                            IgawActivityLifecycleCallbacks.this.commonInterface.custom("IgawCommon", "openIabV3Activity", "");
                                            return;
                                        }
                                    }
                                }
                            } else if (VERSION.SDK_INT >= 21) {
                                List<RunningTaskInfo> runningTasks = activityManager.getRunningTasks(ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED);
                                if (runningTasks != null) {
                                    for (int i = 0; i < runningTasks.size(); i++) {
                                        if (!(runningTasks.get(i) == null || runningTasks.get(i).topActivity == null)) {
                                            String topActivity2 = runningTasks.get(i).topActivity.toString();
                                            IgawLogger.Logging(activity, IgawConstant.QA_TAG, "IgawActivityLifecycleCallbacks onActivityPaused : " + topActivity2, 1, true);
                                            if (topActivity2 != null && topActivity2.contains("IabV3Activity")) {
                                                if (IgawActivityLifecycleCallbacks.this.commonInterface == null) {
                                                    IgawActivityLifecycleCallbacks.this.commonInterface = (CommonFrameworkImpl) CommonFrameworkFactory.getCommonFramework();
                                                }
                                                IgawActivityLifecycleCallbacks.this.commonInterface.custom("IgawCommon", "openIabV3Activity", "");
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                        } catch (SecurityException e) {
                            e.printStackTrace();
                        } catch (NoClassDefFoundError e2) {
                            e2.printStackTrace();
                        } catch (NoSuchMethodError e3) {
                            e3.printStackTrace();
                        } catch (Exception e4) {
                            e4.printStackTrace();
                        }
                    }
                }, 200);
            }
        } catch (Exception e) {
        }
    }

    public void onActivityStopped(Activity activity) {
    }

    public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
    }

    public void onActivityDestroyed(Activity activity) {
    }
}