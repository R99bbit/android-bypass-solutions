package com.loplat.placeengine;

import a.b.a.a.a.d;
import a.b.a.b.l;
import a.b.a.f.a;
import a.b.a.f.i;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import androidx.annotation.DrawableRes;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.annotation.StringRes;
import com.loplat.placeengine.PlengiResponse.Place;
import com.loplat.placeengine.cloud.RequestMessage.Specialty;

public class PlengiBase {
    public static Context mContext;
    public static OnPlengiListener mOnPlengiListener;
    public static PlengiListener mPlengiListener;

    public PlengiBase(Context context) {
        mContext = context;
    }

    public static Context getContext() {
        return mContext;
    }

    public static OnPlengiListener getOnPlengiListener() {
        return mOnPlengiListener;
    }

    public static boolean isPlengiDebugMode() {
        return false;
    }

    public static void setOnPlengiListener(OnPlengiListener onPlengiListener) {
        mOnPlengiListener = onPlengiListener;
    }

    public int TEST_refreshPlace_foreground(OnPlengiListener onPlengiListener) {
        mOnPlengiListener = onPlengiListener;
        return PlaceEngineBase.getPlaceInfoWithNewScan(mContext);
    }

    public void disableForegroundMonitoring(boolean z) {
        PlaceEngineBase.c = z;
    }

    public void enableAdNetwork(boolean z) {
        PlaceEngineBase.enableAdNetwork(mContext, z, true);
    }

    public void enableTestServer(boolean z) {
        l.b();
    }

    public void feedbackAdResult(int i, int i2) {
        PlaceEngineBase.feedbackAdResult(mContext, i, i2);
    }

    public Place getCurrentPlaceInfo() {
        return PlaceEngineBase.getCurrentPlace(mContext);
    }

    public int getCurrentPlaceStatus() {
        return PlaceEngineBase.getCurrentStatus(mContext);
    }

    @RequiresApi(26)
    public String getDefaultNotificationChannelId() {
        return "plengi_default_2";
    }

    public int getEngineStatus() {
        return PlaceEngineBase.getEngineStatus(mContext);
    }

    public PlengiListener getListener() {
        return mPlengiListener;
    }

    public int getMonitoringType() {
        return PlaceEngineBase.getMonitoringType(mContext);
    }

    @RequiresApi(29)
    public void hideNotificationWhileSearchPlace() {
        i.b = false;
    }

    public int init(String str, String str2, String str3) {
        return PlaceEngineBase.init(mContext, str, str2, str3);
    }

    public boolean isEnabledAdNetwork() {
        return PlaceEngineBase.isEnabledAdNetwork(mContext);
    }

    public boolean isTestServerEnabled() {
        l.d();
        return false;
    }

    @RequiresApi(26)
    public void setAdNotiChannelInfo(@StringRes int i, @StringRes int i2) {
        d.f3a = i;
        d.b = i2;
    }

    public void setAdNotiLargeIcon(int i) {
        PlaceEngineBase.setAdNotiLargeIcon(mContext, i);
    }

    public void setAdNotiSmallIcon(int i) {
        PlaceEngineBase.setAdNotiSmallIcon(mContext, i);
    }

    @RequiresApi(26)
    public String setDefaultNotificationChannel(@StringRes int i, @StringRes int i2, @StringRes int i3) {
        a.c = i;
        a.d = i2;
        a.e = i3;
        return "plengi_default_2";
    }

    @RequiresApi(26)
    public void setDefaultNotificationInfo(@DrawableRes int i, @StringRes int i2, @StringRes int i3) {
        a.f = i;
        a.g = i2;
        a.h = i3;
        a.f32a = null;
    }

    public void setListener(PlengiListener plengiListener) {
        mPlengiListener = plengiListener;
    }

    public int setMonitoringType(int i) {
        return PlaceEngineBase.setMonitoringType(mContext, i, false);
    }

    public void setScanPeriod(int i, int i2) {
        PlaceEngineBase.setScanPeriod(mContext, i, i2, false);
    }

    public void setScanPeriodTracking(int i) {
        PlaceEngineBase.setScanPeriodTracking(mContext, i, false);
    }

    public void setSpecialty(Specialty specialty) {
        PlaceEngineBase.setSpecialtyRequest(mContext, specialty);
    }

    @RequiresApi(29)
    public void showNotificationWhileSearchPlace(@NonNull NotificationChannel notificationChannel, @StringRes int i, @StringRes int i2, @DrawableRes int i3) {
        NotificationManager notificationManager = (NotificationManager) mContext.getSystemService("notification");
        if (notificationManager != null) {
            notificationManager.createNotificationChannel(notificationChannel);
        }
        String id = notificationChannel.getId();
        i.b = true;
        i.c = id;
        i.d = i;
        i.e = i2;
        i.f = i3;
        i.f39a = null;
    }

    public int start() {
        return PlaceEngineBase.startPlaceEngine(mContext);
    }

    public int stop() {
        PlaceEngineBase.stopPlaceEngine(mContext);
        return 0;
    }

    @Deprecated
    public void supportDataBase(boolean z) {
    }

    public void enableAdNetwork(boolean z, boolean z2) {
        PlaceEngineBase.enableAdNetwork(mContext, z, z2);
    }

    public int TEST_refreshPlace_foreground(Specialty specialty, OnPlengiListener onPlengiListener) {
        mOnPlengiListener = onPlengiListener;
        return PlaceEngineBase.getPlaceInfoWithNewScan(mContext, specialty);
    }

    @RequiresApi(26)
    public String setDefaultNotificationChannel(@StringRes int i, @StringRes int i2) {
        return setDefaultNotificationChannel(i, i2, 0);
    }

    public int TEST_refreshPlace_foreground() {
        return PlaceEngineBase.getPlaceInfoWithNewScan(mContext);
    }

    @RequiresApi(26)
    public void setDefaultNotificationInfo(@NonNull Notification notification) {
        a.f = 0;
        a.g = 0;
        a.h = 0;
        a.f32a = notification;
    }

    public int TEST_refreshPlace_foreground(Specialty specialty) {
        return PlaceEngineBase.getPlaceInfoWithNewScan(mContext, specialty);
    }
}