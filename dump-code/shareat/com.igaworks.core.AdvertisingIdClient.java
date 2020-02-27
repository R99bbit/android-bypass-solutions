package com.igaworks.core;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences.Editor;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Looper;
import android.os.Parcel;
import android.os.RemoteException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;

public class AdvertisingIdClient {
    private static AdInfo adInfo;
    private static List<ADIDCallbackListener> adidListeners;
    private static boolean onBind = false;

    public interface ADIDCallbackListener {
        void onResult(AdInfo adInfo);
    }

    public static final class AdInfo {
        private final String advertisingId;
        private final boolean limitAdTrackingEnabled;

        AdInfo(String advertisingId2, boolean limitAdTrackingEnabled2) {
            this.advertisingId = advertisingId2;
            this.limitAdTrackingEnabled = limitAdTrackingEnabled2;
        }

        public String getId() {
            return this.advertisingId;
        }

        public boolean isLimitAdTrackingEnabled() {
            return this.limitAdTrackingEnabled;
        }
    }

    private static final class AdvertisingConnection implements ServiceConnection {
        private final LinkedBlockingQueue<IBinder> queue;
        boolean retrieved;

        private AdvertisingConnection() {
            this.retrieved = false;
            this.queue = new LinkedBlockingQueue<>(1);
        }

        /* synthetic */ AdvertisingConnection(AdvertisingConnection advertisingConnection) {
            this();
        }

        public void onServiceConnected(ComponentName name, IBinder service) {
            try {
                this.queue.put(service);
            } catch (InterruptedException e) {
            }
        }

        public void onServiceDisconnected(ComponentName name) {
        }

        public IBinder getBinder() throws InterruptedException {
            if (this.retrieved) {
                throw new IllegalStateException();
            }
            this.retrieved = true;
            return this.queue.take();
        }
    }

    private static final class AdvertisingInterface implements IInterface {
        private IBinder binder;

        public AdvertisingInterface(IBinder pBinder) {
            this.binder = pBinder;
        }

        public IBinder asBinder() {
            return this.binder;
        }

        public String getId() throws RemoteException {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(AdvertisingInterface.ADVERTISING_ID_SERVICE_INTERFACE_TOKEN);
                this.binder.transact(1, data, reply, 0);
                reply.readException();
                return reply.readString();
            } finally {
                reply.recycle();
                data.recycle();
            }
        }

        public boolean isLimitAdTrackingEnabled(boolean paramBoolean) throws RemoteException {
            int i;
            boolean limitAdTracking = true;
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(AdvertisingInterface.ADVERTISING_ID_SERVICE_INTERFACE_TOKEN);
                if (paramBoolean) {
                    i = 1;
                } else {
                    i = 0;
                }
                data.writeInt(i);
                this.binder.transact(2, data, reply, 0);
                reply.readException();
                if (reply.readInt() == 0) {
                    limitAdTracking = false;
                }
                return limitAdTracking;
            } finally {
                reply.recycle();
                data.recycle();
            }
        }
    }

    public static void registADIDListener(ADIDCallbackListener listener) {
        if (adidListeners == null) {
            adidListeners = new ArrayList();
        }
        if (!adidListeners.contains(listener)) {
            adidListeners.add(listener);
        }
    }

    /* JADX WARNING: No exception handlers in catch block: Catch:{  } */
    public static AdInfo getAdvertisingIdInfo(Context context, ADIDCallbackListener listener) throws Exception {
        AdvertisingConnection connection;
        try {
            if (adInfo != null) {
                if (listener != null) {
                    listener.onResult(adInfo);
                }
                return adInfo;
            } else if (Looper.myLooper() == Looper.getMainLooper()) {
                if (listener != null) {
                    listener.onResult(null);
                }
                throw new IllegalStateException("Cannot be called from the main thread");
            } else {
                try {
                    context.getPackageManager().getPackageInfo("com.android.vending", 0);
                    if (!onBind) {
                        onBind = true;
                        try {
                            connection = new AdvertisingConnection(null);
                            Intent intent = new Intent(AdvertisingInfoServiceStrategy.GOOGLE_PLAY_SERVICES_INTENT);
                            intent.setPackage("com.google.android.gms");
                            if (context.bindService(intent, connection, 1)) {
                                AdvertisingInterface adInterface = new AdvertisingInterface(connection.getBinder());
                                adInfo = new AdInfo(adInterface.getId(), adInterface.isLimitAdTrackingEnabled(true));
                                final String adId = adInfo.getId();
                                if (adId != null && adId.length() > 0) {
                                    final Context context2 = context;
                                    new Thread(new Runnable() {
                                        public void run() {
                                            Editor editor = context2.getSharedPreferences("adpopcorn_parameter", 0).edit();
                                            editor.putString(RequestParameter.GOOGLE_AD_ID, adId);
                                            editor.commit();
                                        }
                                    }).start();
                                }
                                AdInfo adInfo2 = adInfo;
                                context.unbindService(connection);
                                onBind = false;
                                onBind = false;
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "onBind > adid request complete, send callback request to listeners.", 3, true);
                                if (listener != null) {
                                    try {
                                        listener.onResult(adInfo);
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                        return adInfo2;
                                    }
                                }
                                if (adidListeners == null || adidListeners.size() <= 0) {
                                    return adInfo2;
                                }
                                List<ADIDCallbackListener> tList = new ArrayList<>(adidListeners);
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "onBind > adidListeners size : " + adidListeners.size(), 3, true);
                                adidListeners.clear();
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "onBind > adidListeners size(after clear) : " + adidListeners.size(), 3, true);
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "onBind > tList size : " + tList.size(), 3, true);
                                for (ADIDCallbackListener item : tList) {
                                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "onBind > send adInfo to adidListeners", 3, true);
                                    item.onResult(adInfo);
                                }
                                tList.clear();
                                return adInfo2;
                            }
                        } catch (Exception exception) {
                            exception.printStackTrace();
                            context.unbindService(connection);
                            onBind = false;
                        } catch (Throwable th) {
                            onBind = false;
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "onBind > adid request complete, send callback request to listeners.", 3, true);
                            if (listener != null) {
                                try {
                                    listener.onResult(adInfo);
                                } catch (Exception e2) {
                                    e2.printStackTrace();
                                    throw th;
                                }
                            }
                            if (adidListeners != null && adidListeners.size() > 0) {
                                List<ADIDCallbackListener> tList2 = new ArrayList<>(adidListeners);
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "onBind > adidListeners size : " + adidListeners.size(), 3, true);
                                adidListeners.clear();
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "onBind > adidListeners size(after clear) : " + adidListeners.size(), 3, true);
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "onBind > tList size : " + tList2.size(), 3, true);
                                for (ADIDCallbackListener item2 : tList2) {
                                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "onBind > send adInfo to adidListeners", 3, true);
                                    item2.onResult(adInfo);
                                }
                                tList2.clear();
                            }
                            throw th;
                        }
                        throw new IOException("Google Play connection failed");
                    }
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "onBind > com.google.android.gms", 3, true);
                    if (listener != null) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "onBind > add to adidListener.", 3, true);
                        registADIDListener(listener);
                    }
                    return null;
                } catch (Exception e3) {
                    if (listener != null) {
                        listener.onResult(null);
                    }
                    return null;
                }
            }
        } catch (Exception e4) {
            if (e4 != null) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, e4.toString(), 0, true);
            }
            return null;
        }
    }
}