package com.loplat.placeengine;

import android.content.Context;
import com.loplat.placeengine.PlengiResponse.Place;

public class Plengi {
    private static Context mContext = null;
    private static Plengi mPlengi = null;
    private static PlengiListener mPlengiListener = null;

    private Plengi(Context context) {
        mContext = context;
    }

    public static synchronized Plengi getInstance(Context context) {
        Plengi plengi;
        synchronized (Plengi.class) {
            try {
                if (mPlengi == null && context != null) {
                    mPlengi = new Plengi(context.getApplicationContext());
                }
                plengi = mPlengi;
            }
        }
        return plengi;
    }

    public void setListener(PlengiListener plengiListener) {
        mPlengiListener = plengiListener;
    }

    public PlengiListener getListener() {
        return mPlengiListener;
    }

    public int init(String clientId, String clientSecret, String uniqueUserId) {
        return a.a(mContext, clientId, clientSecret, uniqueUserId);
    }

    public int isEngineWorkable() {
        return a.l(mContext);
    }

    public int start() {
        return a.b(mContext);
    }

    public int stop() {
        return a.c(mContext);
    }

    public int setMonitoringType(int monitoringType) {
        return a.a(mContext, monitoringType);
    }

    public int getMonitoringType() {
        return a.d(mContext);
    }

    public void setScanPeriod(int movePeriodInMillis, int stayPeriodInMillis) {
        a.a(mContext, movePeriodInMillis, stayPeriodInMillis);
    }

    public void setScanPeriodTracking(int scanPeriodInMillis) {
        a.c(mContext, scanPeriodInMillis);
    }

    public int getCurrentPlaceStatus() {
        return a.e(mContext);
    }

    public Place getCurrentPlaceInfo() {
        return a.f(mContext);
    }

    public int refreshPlace() {
        return a.g(mContext);
    }

    public int getUuidp() {
        return a.h(mContext);
    }

    public int startNearbySession() {
        return a.i(mContext);
    }

    public int stopNearbySession() {
        return a.j(mContext);
    }

    public int getNearbyDeviceList() {
        return a.k(mContext);
    }
}