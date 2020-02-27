package com.igaworks;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.os.Build.VERSION;
import android.util.Log;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;
import com.igaworks.impl.CommonFrameworkFactory;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.impl.InternalAction;
import com.igaworks.interfaces.CommonInterface;
import com.igaworks.interfaces.DeferredLinkListener;
import com.igaworks.interfaces.IgawRewardItemEventListener;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.Task;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class IgawCommon {
    private static boolean autosessiontrackingEnable = false;
    private static CommonInterface commonFrameWork;
    public static ExecutorService igawPubQueue = Executors.newSingleThreadExecutor();

    public interface Gender {
        public static final int FEMALE = 1;
        public static final int MALE = 2;
    }

    public static CommonInterface framework() {
        if (commonFrameWork == null) {
            synchronized (IgawCommon.class) {
                try {
                    if (commonFrameWork == null) {
                        commonFrameWork = CommonFrameworkFactory.getCommonFramework();
                    }
                }
            }
        }
        if (igawPubQueue == null || igawPubQueue.isShutdown()) {
            igawPubQueue = Executors.newSingleThreadExecutor();
        }
        return commonFrameWork;
    }

    public static void startSession(Activity activity) {
        try {
            CommonFrameworkImpl.setContext(activity);
            CommonFrameworkImpl.parameter = RequestParameter.getATRequestParameter(CommonFrameworkImpl.getContext());
            if (autosessiontrackingEnable) {
                IgawLogger.Logging(activity, IgawConstant.QA_TAG, "Called startSession api when autosessiontrackingEnable is true", 1, true);
            } else {
                framework().startSession(activity);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void startSession(Context context) {
        if (!(context instanceof Activity)) {
            Log.e(IgawConstant.QA_TAG, "IgawCommon.startSession API: Context must be Activity Context");
        }
        try {
            CommonFrameworkImpl.setContext(context);
            CommonFrameworkImpl.parameter = RequestParameter.getATRequestParameter(CommonFrameworkImpl.getContext());
            if (autosessiontrackingEnable) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Called startSession api when autosessiontrackingEnable is true", 1, true);
            } else {
                framework().startSession(context);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void endSession() {
        try {
            if (autosessiontrackingEnable) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "Called endSession api when autosessiontrackingEnable is true", 1, true);
            } else {
                framework().endSession();
            }
        } catch (Exception e) {
            Log.e(IgawConstant.QA_TAG, "endSession Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void setAge(final int age) {
        try {
            igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawCommon.framework().setAge(age);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void setGender(final int gender) {
        try {
            igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawCommon.framework().setGender(gender);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void setUserId(final String userId) {
        try {
            if (CommonFrameworkImpl.getContext() == null) {
                Task.delay(1000).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Void, Void>() {
                    public Void then(Task<Void> task) throws Exception {
                        IgawCommon.framework().setUserId(userId);
                        return null;
                    }
                }, (Executor) InternalAction.NETWORK_EXECUTOR);
            } else {
                igawPubQueue.execute(new Runnable() {
                    public void run() {
                        IgawCommon.framework().setUserId(userId);
                    }
                });
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void setUserId(Context context, final String userId) {
        try {
            CommonFrameworkImpl.setContext(context);
            igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawCommon.framework().setUserId(userId);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void autoSessionTracking(Application applicaton) {
        try {
            if (VERSION.SDK_INT >= 15) {
                applicaton.registerActivityLifecycleCallbacks(new IgawActivityLifecycleCallbacks());
                framework().startApplicationForInternalUse(applicaton.getApplicationContext());
                autosessiontrackingEnable = true;
            } else {
                framework().startApplicationForInternalUse(applicaton.getApplicationContext());
                Log.w(IgawConstant.QA_TAG, "IgawCommon.autoSessionTracking API requires minSdkVersion >= 15");
            }
            IgawLogger.Logging(applicaton.getApplicationContext(), IgawConstant.QA_TAG, "called autoSessionTracking", 3, true);
        } catch (Exception e) {
            Log.e(IgawConstant.QA_TAG, "autoSessionTracking Error: " + e.getMessage());
        }
    }

    @Deprecated
    public static void startApplication(Context context) {
        try {
            framework().startApplicationForInternalUse(context);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void registerReferrer(Activity deeplinkActivity) {
        framework().deeplinkConversion(deeplinkActivity, true);
    }

    @Deprecated
    public static void addIntentReceiveror(String componentName) {
        framework().addIntentReceiver(componentName);
    }

    @Deprecated
    public static void removeIntentReceiver(String componentName) {
        framework().removeIntentReceiver(componentName);
    }

    @Deprecated
    public static void clearIntentReceiver() {
        framework().clearIntentReceiver();
    }

    @Deprecated
    public static void viral(final String name) {
        try {
            igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawCommon.framework().viral(name);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void viral(final String name, final String param) {
        try {
            igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawCommon.framework().viral(name, param);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void error(final String errorName, final String detail) {
        try {
            igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawCommon.framework().error(errorName, detail);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void custom(final String name) {
        try {
            igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawCommon.framework().custom(name);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void custom(final String name, final String param) {
        try {
            igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawCommon.framework().custom(name, param);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void onReceiveReferral(Context context) {
        framework().onReceiveReferral(context);
    }

    public static void onReceiveReferral(Context context, String rawParams) {
        framework().onReceiveReferral(context, rawParams);
    }

    public static void setClientRewardEventListener(IgawRewardItemEventListener listener) {
        framework().setClientRewardEventListener(listener);
    }

    public static void setDeferredLinkListener(Context context, DeferredLinkListener listener) {
        framework().setDeferredLinkListener(context, listener);
    }

    @Deprecated
    public static void setReferralUrl(Context context, String deeplinkStr) {
        framework().setReferralUrlForFacebook(context, deeplinkStr);
    }

    public static void setReferralUrlForFacebook(Context context, String deeplinkStr) {
        framework().setReferralUrlForFacebook(context, deeplinkStr);
    }

    public static void protectSessionTracking(Activity activity) {
        Log.d(IgawConstant.QA_TAG, "called protectSessionTracking");
        framework().endSession();
        framework().startSession(activity);
    }
}