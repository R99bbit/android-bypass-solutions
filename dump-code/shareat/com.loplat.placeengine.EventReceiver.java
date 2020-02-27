package com.loplat.placeengine;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Build.VERSION;
import android.support.v4.app.NotificationCompat;
import com.loplat.placeengine.c.a;
import com.loplat.placeengine.utils.LoplatLogger;
import java.util.List;

public class EventReceiver extends BroadcastReceiver {
    public void onReceive(Context context, Intent intent) {
        int processed;
        if (intent != null && context != null) {
            Context plengiContext = context.getApplicationContext();
            String action = intent.getAction();
            if (action == null) {
                return;
            }
            if (a.n(plengiContext) == 0 && a.m(plengiContext) == 0) {
                LoplatLogger.writeLog("EventReceiver: PlaceEngine is stopped");
                return;
            }
            char c = 65535;
            switch (action.hashCode()) {
                case -343630553:
                    if (action.equals("android.net.wifi.STATE_CHANGE")) {
                        c = 3;
                        break;
                    }
                    break;
                case 409953495:
                    if (action.equals("android.net.wifi.WIFI_AP_STATE_CHANGED")) {
                        c = 2;
                        break;
                    }
                    break;
                case 495305082:
                    if (action.equals("com.loplat.placeengine.event.scanwifi")) {
                        c = 1;
                        break;
                    }
                    break;
                case 798292259:
                    if (action.equals("android.intent.action.BOOT_COMPLETED")) {
                        c = 0;
                        break;
                    }
                    break;
                case 1878357501:
                    if (action.equals("android.net.wifi.SCAN_RESULTS")) {
                        c = 4;
                        break;
                    }
                    break;
            }
            switch (c) {
                case 0:
                    LoplatLogger.writeLog("EventReceiver: " + action);
                    a.a(plengiContext);
                    a(plengiContext);
                    return;
                case 1:
                    LoplatLogger.writeLog("EventReceiver: " + action);
                    a(plengiContext);
                    return;
                case 4:
                    LoplatLogger.writeLog("EventReceiver: " + action);
                    List<ScanResult> list = null;
                    if (a.j(plengiContext)) {
                        WifiManager wifiManager = (WifiManager) plengiContext.getSystemService("wifi");
                        if (wifiManager != null) {
                            try {
                                list = wifiManager.getScanResults();
                            } catch (SecurityException e) {
                                LoplatLogger.writeLog("[Exception] get ScanResults: " + e);
                            } catch (RuntimeException e2) {
                                LoplatLogger.writeLog("[Exception] get ScanResults: " + e2);
                            }
                        } else {
                            return;
                        }
                    }
                    if (a.p(plengiContext) == 1) {
                        processed = c.a(plengiContext, list);
                    } else {
                        processed = b.a(plengiContext, list);
                    }
                    a.b(plengiContext, processed);
                    if (processed > 0) {
                        b(plengiContext);
                        if (a.p(plengiContext) == 1) {
                            if (c.c(plengiContext) == 1) {
                                a(plengiContext, a.c(plengiContext));
                                return;
                            } else {
                                a(plengiContext, a.d(plengiContext));
                                return;
                            }
                        } else if (b.h(plengiContext) == 2) {
                            a(plengiContext, a.b(plengiContext));
                            return;
                        } else {
                            a(plengiContext, a.a(plengiContext));
                            return;
                        }
                    } else {
                        return;
                    }
                default:
                    return;
            }
        }
    }

    private void a(Context context) {
        if (a.k(context)) {
            LoplatLogger.writeLog("Hotspot is on, Do not scan Wifi");
            a(context, a.e(context));
        } else if (!a.h(context)) {
            LoplatLogger.writeLog("wifi scanning is not available");
            a(context, a.e(context));
        } else {
            try {
                WifiManager wifi = (WifiManager) context.getSystemService("wifi");
                if (wifi != null) {
                    wifi.startScan();
                    LoplatLogger.writeLog("------> Request Active WiFi Scan");
                }
            } catch (Exception e) {
                LoplatLogger.writeLog("[Exception] start Wifi scan -> " + e);
            }
        }
    }

    private void a(Context context, int time) {
        try {
            PendingIntent alarmIntent = PendingIntent.getBroadcast(context, 0, new Intent("com.loplat.placeengine.event.scanwifi"), 268435456);
            int next_time = time;
            AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
            if (alarmManager != null) {
                if (VERSION.SDK_INT >= 23) {
                    alarmManager.setAndAllowWhileIdle(0, System.currentTimeMillis() + ((long) time), alarmIntent);
                } else {
                    alarmManager.setRepeating(0, System.currentTimeMillis() + ((long) time), (long) next_time, alarmIntent);
                }
                LoplatLogger.writeLog("setWifiTimer: " + time + ", sdk: " + VERSION.SDK_INT);
            }
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set timer error -> " + e);
        }
    }

    private void b(Context context) {
        try {
            PendingIntent alarmIntent = PendingIntent.getBroadcast(context, 0, new Intent("com.loplat.placeengine.event.scanwifi"), 0);
            AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
            if (alarmManager != null) {
                alarmManager.cancel(alarmIntent);
            }
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] cancel timer error -> " + e);
        }
    }
}