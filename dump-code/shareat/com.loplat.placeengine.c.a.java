package com.loplat.placeengine.c;

import android.app.ActivityManager;
import android.app.ActivityManager.RunningServiceInfo;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences.Editor;
import android.content.pm.PackageManager;
import android.location.LocationManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build.VERSION;
import android.support.v4.app.NotificationCompat;
import android.telephony.TelephonyManager;
import com.google.firebase.analytics.FirebaseAnalytics.Param;
import com.loplat.placeengine.a.b;
import com.loplat.placeengine.d.d;
import com.loplat.placeengine.utils.LoplatLogger;
import com.naver.maps.map.overlay.LocationOverlay;
import com.nostra13.universalimageloader.core.download.BaseImageDownloader;
import java.lang.reflect.Method;
import java.util.ArrayList;
import org.json.JSONException;
import org.json.JSONObject;

/* compiled from: StatusManager */
public class a {
    public static void a(Context context, int scanperiod) {
        try {
            Editor editor = context.getSharedPreferences("PLACEENGINE", 0).edit();
            if (scanperiod < 180000) {
                scanperiod = 180000;
            }
            editor.putInt("defaultscanperiod", scanperiod);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set recognizer mode default scan period error: " + e);
        }
    }

    public static void b(Context context, int scanperiod) {
        try {
            Editor editor = context.getSharedPreferences("PLACEENGINE", 0).edit();
            if (scanperiod < 360000) {
                scanperiod = 360000;
            }
            editor.putInt("stayscanperiod", scanperiod);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set recognizer mode scan period for stay error: " + e);
        }
    }

    public static int a(Context context) {
        int period = 180000;
        try {
            return context.getSharedPreferences("PLACEENGINE", 0).getInt("defaultscanperiod", 180000);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get recognizer mode default scan period error: " + e);
            return period;
        }
    }

    public static int b(Context context) {
        int period = 360000;
        try {
            return context.getSharedPreferences("PLACEENGINE", 0).getInt("stayscanperiod", 360000);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get recognizer mode scan period for stay error: " + e);
            return period;
        }
    }

    public static void c(Context context, int scanperiod) {
        try {
            if (u(context)) {
                if (scanperiod < 20000) {
                    scanperiod = BaseImageDownloader.DEFAULT_HTTP_READ_TIMEOUT;
                }
            } else if (scanperiod < 60000) {
                scanperiod = 60000;
            }
            if (d(context) != scanperiod) {
                v(context);
                e(context, scanperiod);
                Editor editor = context.getSharedPreferences("TRACKER", 0).edit();
                LoplatLogger.writeLog("setScanPeriodTracking -> " + scanperiod);
                editor.putInt("trackerscanperiod", scanperiod);
                editor.commit();
            }
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set tracker mode scan period error: " + e);
        }
    }

    public static int c(Context context) {
        try {
            return context.getSharedPreferences("TRACKER", 0).getInt("trackerscanperiod", 120000) * 2;
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get tracker mode scan period for stationary error: " + e);
            return 240000;
        }
    }

    public static int d(Context context) {
        int period = 120000;
        try {
            return context.getSharedPreferences("TRACKER", 0).getInt("trackerscanperiod", 120000);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get tracker mode scan period error: " + e);
            return period;
        }
    }

    public static int e(Context context) {
        return LocationOverlay.DEFAULT_GLOBAL_Z_INDEX;
    }

    public static long f(Context context) {
        return 120000;
    }

    public static boolean g(Context context) {
        NetworkInfo activeNetworkInfo = ((ConnectivityManager) context.getSystemService("connectivity")).getActiveNetworkInfo();
        return activeNetworkInfo != null && activeNetworkInfo.isConnected();
    }

    public static boolean h(Context context) {
        boolean wifiEnabled = false;
        boolean wifiScanEnabled = false;
        try {
            WifiManager wifiManager = (WifiManager) context.getSystemService("wifi");
            if (wifiManager != null) {
                wifiEnabled = wifiManager.isWifiEnabled();
                if (VERSION.SDK_INT >= 18) {
                    wifiScanEnabled = wifiManager.isScanAlwaysAvailable();
                }
            }
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] read Wifi Status: " + e);
        }
        LoplatLogger.writeLog("WiFiScanAvailable: " + wifiEnabled + ", " + wifiScanEnabled);
        if (wifiEnabled || wifiScanEnabled) {
            return true;
        }
        return false;
    }

    public static boolean i(Context context) {
        WifiManager wifi = (WifiManager) context.getSystemService("wifi");
        boolean wifiScanEnabled = false;
        boolean wifiEnabled = false;
        boolean wifiScanAllowable = false;
        try {
            wifiEnabled = wifi.isWifiEnabled();
            if (VERSION.SDK_INT >= 18) {
                wifiScanEnabled = wifi.isScanAlwaysAvailable();
            }
            wifiScanAllowable = j(context);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] read Wifi Status: " + e);
        }
        LoplatLogger.writeLog("WiFiScanAvailable: " + wifiEnabled + ", " + wifiScanEnabled + ", " + wifiScanAllowable);
        if ((wifiEnabled || wifiScanEnabled) && wifiScanAllowable) {
            return true;
        }
        return false;
    }

    public static boolean j(Context context) {
        if (VERSION.SDK_INT < 23) {
            return true;
        }
        boolean isNetworkEnabled = false;
        boolean isGPSEnabled = false;
        LocationManager locationManager = (LocationManager) context.getSystemService(Param.LOCATION);
        if (locationManager != null) {
            try {
                isNetworkEnabled = locationManager.isProviderEnabled("network");
                isGPSEnabled = locationManager.isProviderEnabled("gps");
            } catch (Exception e) {
                LoplatLogger.writeLog("[Exception] check GPS provider: " + e);
            }
        }
        LoplatLogger.printLog("GPS: " + isGPSEnabled + ", Network: " + isNetworkEnabled);
        int permission = -1;
        int subpermission = -1;
        PackageManager pm = context.getPackageManager();
        if (pm != null) {
            try {
                permission = pm.checkPermission("android.permission.ACCESS_FINE_LOCATION", context.getPackageName());
                subpermission = pm.checkPermission("android.permission.ACCESS_COARSE_LOCATION", context.getPackageName());
            } catch (Exception e2) {
                LoplatLogger.writeLog("[Exception] check LOCATION permission: " + e2);
            }
        }
        LoplatLogger.printLog("Permission: " + permission + ", " + subpermission);
        if ((isNetworkEnabled || isGPSEnabled) && (permission == 0 || subpermission == 0)) {
            return true;
        }
        return false;
    }

    public static boolean k(Context context) {
        WifiManager wifiManager = (WifiManager) context.getSystemService("wifi");
        boolean enabled = false;
        try {
            Method method = wifiManager.getClass().getDeclaredMethod("isWifiApEnabled", new Class[0]);
            method.setAccessible(true);
            return ((Boolean) method.invoke(wifiManager, new Object[0])).booleanValue();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] check if wifi ap is enabled error: " + e);
            return enabled;
        }
    }

    public static void a(Context context, String clientCode) {
        try {
            Editor editor = context.getSharedPreferences("PLACEENGINE", 0).edit();
            editor.putString("clientcode", clientCode);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set client code error: " + e);
        }
    }

    public static String l(Context context) {
        String clientCode = null;
        try {
            return context.getSharedPreferences("PLACEENGINE", 0).getString("clientcode", null);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get client code error: " + e);
            return clientCode;
        }
    }

    public static void m(Context context) {
        try {
            Editor editor = context.getSharedPreferences("PLACEENGINE", 0).edit();
            editor.putLong("exittime", System.currentTimeMillis());
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set exit time error: " + e);
        }
    }

    public static boolean n(Context context) {
        String clientId = b.d(context);
        if (clientId != null && !clientId.equals("nexon")) {
            return true;
        }
        return false;
    }

    public static boolean o(Context context) {
        String clientId = b.d(context);
        if (clientId != null && !clientId.equals("nexon")) {
            return true;
        }
        return false;
    }

    public static void d(Context context, int monitoringType) {
        try {
            Editor editor = context.getSharedPreferences("PLACEENGINE", 0).edit();
            editor.putInt("monitoringType", monitoringType);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set monitoring type error: " + e);
        }
    }

    public static int p(Context context) {
        int type = 0;
        try {
            return context.getSharedPreferences("PLACEENGINE", 0).getInt("monitoringType", 0);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get monitoring type error: " + e);
            return type;
        }
    }

    public static String q(Context context) {
        String packageName = context.getPackageName();
        LoplatLogger.printLog("Package Name: " + packageName);
        return packageName;
    }

    public static String a() {
        LoplatLogger.printLog("SDK Name: 1.7.8");
        return "1.7.8";
    }

    public static ArrayList<Integer> r(Context context) {
        ArrayList<Integer> list = new ArrayList<>();
        try {
            TelephonyManager manager = (TelephonyManager) context.getSystemService("phone");
            if (manager != null) {
                String networkOperator = manager.getNetworkOperator();
                if (networkOperator != null && networkOperator.length() > 0) {
                    LoplatLogger.printLog("Operator: " + networkOperator);
                    int mcc = Integer.parseInt(networkOperator.substring(0, 3));
                    int mnc = Integer.parseInt(networkOperator.substring(3));
                    list.add(Integer.valueOf(mcc));
                    list.add(Integer.valueOf(mnc));
                    LoplatLogger.printLog("MCC: " + mcc + ", MNC: " + mnc);
                }
            }
        } catch (SecurityException e) {
            LoplatLogger.writeLog("[Exception] get mcc/mnc error: " + e);
        } catch (RuntimeException e2) {
            LoplatLogger.writeLog("[Exception] mcc/mnc error: " + e2);
        }
        return list;
    }

    public static JSONObject s(Context context) {
        JSONObject jsonObject = new JSONObject();
        try {
            ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService("connectivity");
            if (connectivityManager != null) {
                NetworkInfo networkInfo = connectivityManager.getActiveNetworkInfo();
                if (networkInfo != null && networkInfo.isConnected() && networkInfo.getType() == 1) {
                    WifiManager wifiManager = (WifiManager) context.getSystemService("wifi");
                    if (wifiManager != null) {
                        WifiInfo wifiInfo = wifiManager.getConnectionInfo();
                        if (wifiInfo != null) {
                            String bssid = wifiInfo.getBSSID();
                            String ssid = wifiInfo.getSSID();
                            if (ssid == null) {
                                ssid = "";
                            } else if (ssid.startsWith("\"") && wifiInfo.getSSID().endsWith("\"")) {
                                ssid = wifiInfo.getSSID().substring(1, wifiInfo.getSSID().length() - 1);
                            }
                            int frequency = 0;
                            if (VERSION.SDK_INT >= 21) {
                                frequency = wifiInfo.getFrequency();
                            }
                            int rss = wifiInfo.getRssi();
                            try {
                                jsonObject.put("network", "wifi");
                                jsonObject.put("bssid", bssid);
                                jsonObject.put("ssid", ssid);
                                jsonObject.put("rss", rss);
                                if (frequency > 0) {
                                    jsonObject.put("frequency", frequency);
                                }
                            } catch (JSONException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        return jsonObject;
    }

    public static d t(Context context) {
        try {
            NetworkInfo networkInfo = ((ConnectivityManager) context.getSystemService("connectivity")).getActiveNetworkInfo();
            if (networkInfo == null || !networkInfo.isConnected() || networkInfo.getType() != 1) {
                return null;
            }
            WifiInfo wifiInfo = ((WifiManager) context.getSystemService("wifi")).getConnectionInfo();
            if (wifiInfo == null) {
                return null;
            }
            String bssid = wifiInfo.getBSSID();
            int frequency = 0;
            if (VERSION.SDK_INT >= 21) {
                frequency = wifiInfo.getFrequency();
            }
            int level = wifiInfo.getRssi();
            String ssid = wifiInfo.getSSID();
            if (ssid == null) {
                ssid = "";
            } else if (ssid.startsWith("\"") && wifiInfo.getSSID().endsWith("\"")) {
                ssid = wifiInfo.getSSID().substring(1, wifiInfo.getSSID().length() - 1);
            }
            return new d(bssid, ssid, level, frequency);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get WifiManager to check wifi connection info: " + e);
            return null;
        }
    }

    public static boolean u(Context context) {
        String clientId = b.d(context);
        if (clientId != null && clientId.equals("jinair")) {
            return true;
        }
        return false;
    }

    public static boolean b(Context context, String serviceName) {
        ActivityManager activityManager = (ActivityManager) context.getSystemService("activity");
        if (activityManager != null) {
            for (RunningServiceInfo runningServiceInfo : activityManager.getRunningServices(ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED)) {
                if (serviceName.equals(runningServiceInfo.service.getClassName())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static void e(Context context, int time) {
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

    private static void v(Context context) {
        try {
            PendingIntent alarmIntent = PendingIntent.getBroadcast(context, 0, new Intent("com.loplat.placeengine.event.scanwifi"), 0);
            AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
            if (alarmManager != null) {
                alarmManager.cancel(alarmIntent);
                LoplatLogger.writeLog("cancel wifi timer");
            }
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] cancel timer error -> " + e);
        }
    }
}