package com.nuvent.shareat;

import android.app.Activity;
import android.app.Application;
import android.app.Application.ActivityLifecycleCallbacks;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager.NameNotFoundException;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.NetworkInfo.State;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Handler;
import android.provider.Settings.Secure;
import android.support.multidex.MultiDexApplication;
import android.telephony.TelephonyManager;
import com.crashlytics.android.Crashlytics;
import com.crashlytics.android.answers.Answers;
import com.facebook.FacebookSdk;
import com.facebook.login.LoginManager;
import com.google.android.gms.ads.identifier.AdvertisingIdClient;
import com.google.android.gms.ads.identifier.AdvertisingIdClient.Info;
import com.google.android.gms.analytics.GoogleAnalytics;
import com.google.android.gms.analytics.Tracker;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.firebase.analytics.FirebaseAnalytics;
import com.igaworks.IgawCommon;
import com.igaworks.core.RequestParameter;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.loplat.placeengine.Plengi;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.main.ActionGuideActivity;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.SocketInfoApi;
import com.nuvent.shareat.api.common.PushTokenRegistApi;
import com.nuvent.shareat.api.member.AvatarUploadApi;
import com.nuvent.shareat.event.GpsRegistEvent;
import com.nuvent.shareat.event.RequestProfileUpdateEvent;
import com.nuvent.shareat.manager.GpsManager;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.manager.socket.SocketInterface;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.SocketResultModel;
import com.nuvent.shareat.receiver.LoplatPlengiListener;
import com.nuvent.shareat.util.AES;
import de.greenrobot.event.EventBus;
import io.fabric.sdk.android.Fabric;
import io.fabric.sdk.android.services.common.CommonUtils;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Observable;
import java.util.Observer;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import net.xenix.util.ImageDisplay;

public class ShareatApp extends MultiDexApplication implements Observer {
    static final boolean DEBUG = false;
    public static final int MEMORY_CHECK_ALL = 0;
    public static final int MEMORY_CHECK_EMULATOR = 3;
    public static final int MEMORY_CHECK_ROOT = 2;
    public static final int MEMORY_CHECK_TOOL = 1;
    public static final int NETWORK_CONNECT = 1;
    public static final int NETWORK_DISCONNECT = -1;
    public static final int NETWORK_NONE = 0;
    public static final String PREFERENCE_NAME = "com.nuvent.shareat";
    private static ShareatApp mInstance;
    private final String SENDER_ID = "780755091338";
    private Listener foregroundListener = null;
    private boolean isQuickPayClick = false;
    public Map<Integer, String> mAppCheckResult = new HashMap();
    private long mAppStartTime;
    private Activity mCurrentActivity = null;
    private FirebaseAnalytics mFirebaseAnalytics;
    private GpsManager mGps;
    /* access modifiers changed from: private */
    public BroadcastReceiver mNetReceiver = new BroadcastReceiver() {
        public void onReceive(Context context, Intent intent) {
            if (intent.getAction().equals("android.net.conn.CONNECTIVITY_CHANGE")) {
                try {
                    ConnectivityManager conMan = (ConnectivityManager) context.getSystemService("connectivity");
                    if (VERSION.SDK_INT >= 23) {
                        NetworkInfo activityNetwork = conMan.getActiveNetworkInfo();
                        if (activityNetwork != null) {
                            if (1 != activityNetwork.getType() && activityNetwork.getType() != 0) {
                                return;
                            }
                            if ((State.CONNECTED == activityNetwork.getState() || State.CONNECTING == activityNetwork.getState()) && ShareatApp.this.mNetWorkStatus != 1) {
                                ShareatApp.this.mNetWorkStatus = 1;
                                ShareatApp.this.mNetWorkObserver.onChangeNetWork(Boolean.valueOf(true));
                            }
                        } else if (ShareatApp.this.mNetWorkStatus != -1) {
                            ShareatApp.this.mNetWorkStatus = -1;
                            ShareatApp.this.mNetWorkObserver.onChangeNetWork(Boolean.valueOf(false));
                        }
                    } else {
                        conMan.getNetworkInfo(0);
                        State wifi = conMan.getNetworkInfo(1).getState();
                        State mobile = conMan.getNetworkInfo(0).getState();
                        if (wifi == State.CONNECTED || wifi == State.CONNECTING) {
                            if (ShareatApp.this.mNetWorkStatus != 1) {
                                ShareatApp.this.mNetWorkStatus = 1;
                                ShareatApp.this.mNetWorkObserver.onChangeNetWork(Boolean.valueOf(true));
                            }
                        } else if (mobile == State.CONNECTED || mobile == State.CONNECTING) {
                            if (ShareatApp.this.mNetWorkStatus != 1) {
                                ShareatApp.this.mNetWorkStatus = 1;
                                ShareatApp.this.mNetWorkObserver.onChangeNetWork(Boolean.valueOf(true));
                            }
                        } else if (ShareatApp.this.mNetWorkStatus != -1) {
                            ShareatApp.this.mNetWorkStatus = -1;
                            ShareatApp.this.mNetWorkObserver.onChangeNetWork(Boolean.valueOf(false));
                        }
                    }
                } catch (NullPointerException e) {
                    e.printStackTrace();
                }
            }
        }
    };
    /* access modifiers changed from: private */
    public NetWorkObserver mNetWorkObserver;
    public int mNetWorkStatus = 0;
    private boolean mPayFlowing = false;
    Plengi mPlengi = null;
    /* access modifiers changed from: private */
    public String mRegId;
    private SocketInterface mSocketManager;
    private long mStartSearchTime = 0;
    private Map<TrackerName, Tracker> trackers = new HashMap();

    private class CheckSecure extends AsyncTask<Void, Void, Boolean> {
        private Context context;

        public CheckSecure(Context context2) {
            this.context = context2;
        }

        /* access modifiers changed from: protected */
        public void onPreExecute() {
            super.onPreExecute();
        }

        /* access modifiers changed from: protected */
        public Boolean doInBackground(Void... args) {
            return Boolean.valueOf(ShareatApp.this.detectHack(this.context));
        }

        /* access modifiers changed from: protected */
        public void onPostExecute(Boolean result) {
        }
    }

    public static class Foreground implements ActivityLifecycleCallbacks {
        public static final long CHECK_DELAY = 500;
        public static final String TAG = Foreground.class.getName();
        private static Foreground instance;
        private Runnable check;
        /* access modifiers changed from: private */
        public boolean foreground = false;
        private Handler handler = new Handler();
        /* access modifiers changed from: private */
        public List<Listener> listeners = new CopyOnWriteArrayList();
        /* access modifiers changed from: private */
        public boolean paused = true;

        public interface Listener {
            void onBecameBackground();

            void onBecameForeground();
        }

        public static Foreground init(Application application) {
            if (instance == null) {
                instance = new Foreground();
                application.registerActivityLifecycleCallbacks(instance);
            }
            return instance;
        }

        public static Foreground get(Application application) {
            if (instance == null) {
                init(application);
            }
            return instance;
        }

        public static Foreground get(Context ctx) {
            if (instance != null) {
                return instance;
            }
            Context appCtx = ctx.getApplicationContext();
            if (appCtx instanceof Application) {
                init((Application) appCtx);
            }
            throw new IllegalStateException("Foreground is not initialised and cannot obtain the Application object");
        }

        public static Foreground get() {
            if (instance != null) {
                return instance;
            }
            throw new IllegalStateException("Foreground is not initialised - invoke at least once with parameterised init/get");
        }

        public boolean isForeground() {
            return this.foreground;
        }

        public boolean isBackground() {
            return !this.foreground;
        }

        public void addListener(Listener listener) {
            this.listeners.add(listener);
        }

        public void removeListener(Listener listener) {
            this.listeners.remove(listener);
        }

        public void onActivityResumed(Activity activity) {
            boolean wasBackground = false;
            this.paused = false;
            if (!this.foreground) {
                wasBackground = true;
            }
            this.foreground = true;
            if (this.check != null) {
                this.handler.removeCallbacks(this.check);
            }
            if (wasBackground) {
                for (Listener l : this.listeners) {
                    try {
                        l.onBecameForeground();
                    } catch (Exception e) {
                    }
                }
            }
        }

        public void onActivityPaused(Activity activity) {
            this.paused = true;
            if (this.check != null) {
                this.handler.removeCallbacks(this.check);
            }
            Handler handler2 = this.handler;
            AnonymousClass1 r1 = new Runnable() {
                public void run() {
                    if (Foreground.this.foreground && Foreground.this.paused) {
                        Foreground.this.foreground = false;
                        for (Listener l : Foreground.this.listeners) {
                            try {
                                l.onBecameBackground();
                            } catch (Exception e) {
                            }
                        }
                    }
                }
            };
            this.check = r1;
            handler2.postDelayed(r1, 500);
        }

        public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
        }

        public void onActivityStarted(Activity activity) {
        }

        public void onActivityStopped(Activity activity) {
        }

        public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
        }

        public void onActivityDestroyed(Activity activity) {
        }
    }

    public class NetWorkObserver extends Observable {
        public NetWorkObserver() {
        }

        public void onChangeNetWork(Object data) {
            try {
                setChanged();
                notifyObservers(data);
            } catch (Exception e) {
                System.out.println(e.toString());
            }
        }
    }

    public enum TrackerName {
        APP_TRACKER,
        GLOBAL_TRACKER,
        ECOMMERCE_TRACKER
    }

    public Activity getCurrentActivity() {
        return this.mCurrentActivity;
    }

    public static Context getContext() {
        return mInstance;
    }

    public void setCurrentActivity(Activity mCurrentActivity2) {
        this.mCurrentActivity = mCurrentActivity2;
    }

    public boolean isPayFlowing() {
        return this.mPayFlowing;
    }

    public void setPayFlowing(boolean _payFlowing) {
        this.mPayFlowing = _payFlowing;
    }

    public void setQuickPayClick(boolean isClick) {
        this.isQuickPayClick = isClick;
    }

    public boolean getQuickPayClick() {
        return this.isQuickPayClick;
    }

    public void update(Observable observable, Object data) {
        if (observable instanceof NetWorkObserver) {
            Boolean isConnectNetwork = (Boolean) data;
            if (getCurrentActivity() != null) {
                if (isConnectNetwork.booleanValue()) {
                    ((BaseActivity) getCurrentActivity()).closeDialog();
                } else {
                    ((BaseActivity) getCurrentActivity()).showDialog(getResources().getString(R.string.COMMON_NETWORK_ERROR));
                }
            }
        } else if (data != null) {
            EventBus.getDefault().post(new GpsRegistEvent(data));
        }
    }

    public void showGlobalAlert(String message, Runnable run) {
        if (getCurrentActivity() != null) {
            ((BaseActivity) getCurrentActivity()).showConfirmDialog(message, run, getCurrentActivity());
        }
    }

    public void showGpsAlert() {
        String strGpsMsg = getResources().getString(R.string.GPS_MSG);
        if (VERSION.SDK_INT >= 23) {
            strGpsMsg = getResources().getString(R.string.GPS_MARSHMALLOW_MSG);
        }
        showGlobalAlert(strGpsMsg, new Runnable() {
            public void run() {
                if (!AppSettingManager.getInstance().getMainListActionGuideStatus()) {
                    ShareatApp.this.getCurrentActivity().startActivity(new Intent(ShareatApp.this.getBaseContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "main"));
                    ShareatApp.this.getCurrentActivity().overridePendingTransition(R.anim.fade_in_activity, R.anim.fade_out_activity);
                }
                ShareatApp.this.getCurrentActivity().startActivity(new Intent("android.settings.LOCATION_SOURCE_SETTINGS"));
            }
        });
    }

    public static synchronized ShareatApp getInstance() {
        ShareatApp shareatApp;
        synchronized (ShareatApp.class) {
            try {
                if (mInstance == null) {
                    mInstance = new ShareatApp();
                }
                shareatApp = mInstance;
            }
        }
        return shareatApp;
    }

    public synchronized Tracker getTracker(TrackerName trackerName) {
        Tracker tracker;
        if (!this.trackers.containsKey(trackerName)) {
            GoogleAnalytics analytics = GoogleAnalytics.getInstance(this);
            analytics.getLogger().setLogLevel(0);
            if (BuildConfig.FLAVOR.equals("develop")) {
                tracker = analytics.newTracker((int) R.xml.global_tracker_debug);
            } else {
                tracker = analytics.newTracker((int) R.xml.global_tracker);
            }
            tracker.enableExceptionReporting(true);
            tracker.enableAutoActivityTracking(false);
            tracker.enableAdvertisingIdCollection(true);
            this.trackers.put(trackerName, tracker);
        }
        return this.trackers.get(trackerName);
    }

    private void setFabric() {
        Fabric.with(this, new Crashlytics());
        Fabric.with(this, new Answers(), new Crashlytics());
    }

    private void setFirebase() {
        this.mFirebaseAnalytics = FirebaseAnalytics.getInstance(this);
    }

    private void setIGAWorks() {
        IgawCommon.autoSessionTracking(this);
    }

    public void onCreate() {
        super.onCreate();
        setFabric();
        setFirebase();
        setIGAWorks();
        mInstance = this;
        ImageDisplay.getInstance().initImageLoader(getInstance());
        if (checkPlayServices()) {
            if (SessionManager.getInstance().getPushToken().isEmpty()) {
                registerInBackground();
            }
            registerInBackgroundForAdID();
        }
        this.mPlengi = Plengi.getInstance(this);
        this.mPlengi.setListener(new LoplatPlengiListener());
        getInstance().addNetworkObserver(this);
        Foreground.init(this);
        this.foregroundListener = new Listener() {
            public void onBecameForeground() {
                if (ShareatApp.this.getGpsManager() != null) {
                    ShareatApp.this.getGpsManager().startGPSListener();
                }
                if (ShareatApp.this.mNetWorkObserver != null) {
                    ShareatApp.getInstance().registerNetworkReceiver();
                }
            }

            public void onBecameBackground() {
                if (ShareatApp.this.getGpsManager() != null) {
                    ShareatApp.this.getGpsManager().stopGPSListener();
                }
                if (ShareatApp.this.mNetWorkObserver != null) {
                    ShareatApp.getInstance().unregisterReceiver(ShareatApp.this.mNetReceiver);
                }
            }
        };
        Foreground.get((Application) this).addListener(this.foregroundListener);
    }

    public Map<Integer, String> getHackToolCheckResult() {
        return this.mAppCheckResult;
    }

    public void checkSecure() {
        new CheckSecure(getInstance()).execute(new Void[0]);
    }

    public boolean detectHack(Context context) {
        return true;
    }

    public void clearSession() {
        SessionManager.getInstance().clearSession();
        if (FacebookSdk.isInitialized()) {
            LoginManager.getInstance().logOut();
        }
    }

    public void setAppStartTime(long sTime) {
        this.mAppStartTime = sTime;
    }

    public long getAppStartTime() {
        return this.mAppStartTime;
    }

    public void setGpsManager(GpsManager gpsManager) {
        this.mGps = gpsManager;
        if (this.mGps != null && this.mGps.getGpsObserver() != null) {
            this.mGps.getGpsObserver().addObserver(this);
        }
    }

    public GpsManager getGpsManager() {
        return this.mGps;
    }

    public String getAppVersionName() {
        try {
            return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (NameNotFoundException e) {
            e.printStackTrace();
            return "";
        }
    }

    public String getPhonenumber() {
        String phoneNumber;
        try {
            phoneNumber = ((TelephonyManager) getSystemService("phone")).getLine1Number();
            if (phoneNumber != null && phoneNumber.length() > 11) {
                phoneNumber = 0 + phoneNumber.substring(phoneNumber.length() - 10);
            }
        } catch (Exception e) {
            e.printStackTrace();
            phoneNumber = "010";
        }
        return phoneNumber == null ? "01000000000" : phoneNumber;
    }

    public String getGUID() {
        try {
            return new UUID((long) ("" + Secure.getString(getContentResolver(), RequestParameter.ANDROID_ID)).hashCode(), (((long) "".hashCode()) << 32) | ((long) ("" + ((TelephonyManager) getSystemService("phone")).getSimSerialNumber()).hashCode())).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "denied_permission";
        }
    }

    public String getUserNum() {
        String token = AES.decrypt(SessionManager.getInstance().getAuthToken());
        try {
            return (String) token.subSequence(0, token.indexOf("|"));
        } catch (Exception e) {
            return token.split("|")[0];
        }
    }

    public static void requestAvatarImageApi(final String filePath) {
        AvatarUploadApi request = new AvatarUploadApi(getInstance());
        request.addFile("file", filePath);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                if (((BaseResultModel) result).getResult().equals("Y")) {
                    EventBus.getDefault().post(new RequestProfileUpdateEvent());
                    File file = new File(filePath);
                    if (file.getParentFile().getName().equals(".temp")) {
                        file.delete();
                    }
                }
            }
        });
    }

    public static void requestSocketUrlUpdate() {
        new SocketInfoApi(getInstance()).request(new RequestHandler() {
            public void onResult(Object result) {
                SocketResultModel model = (SocketResultModel) result;
                if (model.getResult().equals("Y")) {
                    AppSettingManager.getInstance().setSocketUrl(model.getSocket_info().getProtocol() + "://" + model.getSocket_info().getHost() + ":" + model.getSocket_info().getPort());
                } else {
                    AppSettingManager.getInstance().setSocketUrl(ApiUrl.SOCKET_IO_URL);
                }
            }
        });
    }

    public boolean isNetworkConnect() {
        return this.mNetWorkStatus == 1;
    }

    public void addNetworkObserver(Observer observer) {
        if (this.mNetWorkObserver == null) {
            this.mNetWorkObserver = new NetWorkObserver();
            this.mNetWorkObserver.addObserver(observer);
        }
    }

    public void registerNetworkReceiver() {
        registerReceiver(this.mNetReceiver, new IntentFilter("android.net.conn.CONNECTIVITY_CHANGE"));
    }

    public void registPushTokenApi() {
        if (!SessionManager.getInstance().getPushToken().isEmpty()) {
            PushTokenRegistApi api = new PushTokenRegistApi(this);
            api.addParam("regId", SessionManager.getInstance().getPushToken());
            api.addParam("adId", SessionManager.getInstance().getAdID());
            api.addParam("phone_os", "A");
            api.addParam("guid", getInstance().getGUID());
            api.request(new RequestHandler() {
                public void onStart() {
                    super.onStart();
                }

                public void onProgress(int bytesWritten, int totalSize) {
                    super.onProgress(bytesWritten, totalSize);
                }

                public void onResult(Object result) {
                    super.onResult(result);
                    if (((BaseResultModel) result).getResult().equals("Y")) {
                    }
                }

                public void onFailure(Exception exception) {
                    super.onFailure(exception);
                }

                public void onFinish() {
                    super.onFinish();
                }
            });
        }
    }

    public void registPushTokenApi(final Runnable finish) {
        if (!SessionManager.getInstance().getPushToken().isEmpty()) {
            PushTokenRegistApi api = new PushTokenRegistApi(this);
            api.addParam("regId", SessionManager.getInstance().getPushToken());
            api.addParam("adId", SessionManager.getInstance().getAdID());
            api.addParam("phone_os", "A");
            api.addParam("guid", getInstance().getGUID());
            api.request(new RequestHandler() {
                public void onStart() {
                    super.onStart();
                }

                public void onProgress(int bytesWritten, int totalSize) {
                    super.onProgress(bytesWritten, totalSize);
                }

                public void onResult(Object result) {
                    super.onResult(result);
                    if (((BaseResultModel) result).getResult().equals("Y")) {
                    }
                }

                public void onFailure(Exception exception) {
                    super.onFailure(exception);
                }

                public void onFinish() {
                    super.onFinish();
                    if (finish != null) {
                        finish.run();
                    }
                }
            });
        }
    }

    public void setSocketManager(SocketInterface socketManager) {
        this.mSocketManager = socketManager;
    }

    public SocketInterface getSocketManager() {
        return this.mSocketManager;
    }

    private void registerInBackground() {
        new AsyncTask<Void, Void, String>() {
            /* access modifiers changed from: protected */
            public String doInBackground(Void... params) {
                return ShareatApp.this.mRegId;
            }

            /* access modifiers changed from: protected */
            public void onPostExecute(String msg) {
                SessionManager.getInstance().setPushToken(msg);
            }
        }.execute(new Void[]{null, null, null});
    }

    public void registerInBackgroundForAdID() {
        new AsyncTask<Void, Void, String>() {
            /* access modifiers changed from: protected */
            public String doInBackground(Void... params) {
                Info idInfo = null;
                try {
                    idInfo = AdvertisingIdClient.getAdvertisingIdInfo(ShareatApp.this.getApplicationContext());
                } catch (GooglePlayServicesNotAvailableException e) {
                    e.printStackTrace();
                } catch (GooglePlayServicesRepairableException e2) {
                    e2.printStackTrace();
                } catch (IOException e3) {
                    e3.printStackTrace();
                }
                try {
                    if (!idInfo.isLimitAdTrackingEnabled()) {
                        return idInfo.getId();
                    }
                    return "";
                } catch (NullPointerException e4) {
                    e4.printStackTrace();
                    return "";
                }
            }

            /* access modifiers changed from: protected */
            public void onPostExecute(String AdID) {
                SessionManager.getInstance().setAdID(AdID);
            }
        }.execute(new Void[]{null, null, null});
    }

    private boolean checkPlayServices() {
        if (GooglePlayServicesUtil.isGooglePlayServicesAvailable(this) != 0) {
            return false;
        }
        return true;
    }

    public static boolean isEmulator() {
        if (Build.FINGERPRINT.startsWith("generic") || Build.FINGERPRINT.startsWith("unknown") || Build.MODEL.contains(CommonUtils.GOOGLE_SDK) || Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK built for x86") || Build.MANUFACTURER.contains("Genymotion") || ((Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) || CommonUtils.GOOGLE_SDK.equals(Build.PRODUCT))) {
            return true;
        }
        return false;
    }

    public void setStartSearchTime(long lTime) {
        this.mStartSearchTime = lTime;
    }

    public long getStartSearchTime() {
        return this.mStartSearchTime;
    }

    public static void LOG_INFO(String message) {
    }
}