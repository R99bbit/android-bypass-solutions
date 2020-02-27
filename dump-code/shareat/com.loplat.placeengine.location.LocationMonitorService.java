package com.loplat.placeengine.location;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences.Editor;
import android.location.GpsStatus.Listener;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;
import com.google.firebase.analytics.FirebaseAnalytics.Param;
import com.loplat.placeengine.b;
import com.loplat.placeengine.utils.LoplatLogger;
import org.jboss.netty.handler.codec.rtsp.RtspHeaders.Values;

public class LocationMonitorService extends Service implements Listener, LocationListener {
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            String command = intent.getStringExtra("command");
            if (command != null && command.equals("singleupdate")) {
                String provider = a();
                if (provider != null) {
                    LocationManager locationManager = (LocationManager) getSystemService(Param.LOCATION);
                    if (locationManager != null) {
                        try {
                            locationManager.requestLocationUpdates(provider, 0, 0.0f, this);
                        } catch (SecurityException e) {
                            LoplatLogger.writeLog("[Exception] request location updates error: " + e);
                        } catch (NullPointerException e2) {
                            LoplatLogger.writeLog("[Exception] request location updates error: " + e2);
                        }
                    }
                }
            }
        }
        return super.onStartCommand(intent, flags, startId);
    }

    public void onLocationChanged(Location location) {
        LoplatLogger.writeLog("onLocationChanged: " + location.getLatitude() + ", " + location.getLongitude() + ", " + location.getAccuracy());
        a((Context) this, location);
        b.a(this, location.getLatitude(), location.getLongitude(), location.getAccuracy(), 0.0f);
        LocationManager locationManager = (LocationManager) getSystemService(Param.LOCATION);
        if (locationManager != null) {
            try {
                locationManager.removeUpdates(this);
            } catch (SecurityException e) {
                LoplatLogger.writeLog("[Exception] remove location updates error: " + e);
            } catch (NullPointerException e2) {
                LoplatLogger.writeLog("[Exception] remove location updates error: " + e2);
            }
        }
        Log.d("LocationMonitorService", "Location Changed: " + 0.0f + ", " + location.getProvider() + ", " + location.getAccuracy());
    }

    public void onStatusChanged(String s, int i, Bundle bundle) {
        Log.d("LocationMonitorService", "onStatusChanged: " + s);
    }

    public void onProviderEnabled(String s) {
        Log.d("LocationMonitorService", "onProviderEnabled: " + s);
    }

    public void onProviderDisabled(String s) {
        Log.d("LocationMonitorService", "onProviderDisabled: " + s);
    }

    public void onGpsStatusChanged(int event) {
        Log.d("LocationMonitorService", "onGpsStatusChanged: " + event);
        switch (event) {
            case 1:
                a((Context) this, 0);
                return;
            case 4:
                int gpsTry = a(this) + 1;
                if (gpsTry > 10) {
                    LocationManager locationManager = (LocationManager) getSystemService(Param.LOCATION);
                    if (locationManager != null) {
                        try {
                            locationManager.removeUpdates(this);
                        } catch (SecurityException e) {
                            LoplatLogger.writeLog("[Exception] remove location updates error: " + e);
                        } catch (NullPointerException e2) {
                            LoplatLogger.writeLog("[Exception] remove location updates error: " + e2);
                        }
                    }
                }
                a((Context) this, gpsTry);
                return;
            default:
                return;
        }
    }

    public IBinder onBind(Intent intent) {
        return null;
    }

    private String a() {
        boolean isGPSEnabled = false;
        boolean isNetworkEnabled = false;
        LocationManager locationManager = (LocationManager) getSystemService(Param.LOCATION);
        if (locationManager != null) {
            try {
                isNetworkEnabled = locationManager.isProviderEnabled("network");
                isGPSEnabled = locationManager.isProviderEnabled("gps");
            } catch (Exception e) {
                LoplatLogger.writeLog("[Exception] get GPS provider error: " + e);
            }
        }
        if (!isGPSEnabled && !isNetworkEnabled) {
            return null;
        }
        if (isNetworkEnabled) {
            return "network";
        }
        if (isGPSEnabled) {
            return "gps";
        }
        return null;
    }

    public static void a(Context context, int gpstry) {
        try {
            Editor editor = context.getSharedPreferences("LOC_STATUS", 0).edit();
            editor.putInt("gpstry", gpstry);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set gps try error: " + e);
        }
    }

    public static int a(Context context) {
        int gpsTry = 0;
        try {
            return context.getSharedPreferences("LOC_STATUS", 0).getInt("gpstry", 0);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get gps try error: " + e);
            return gpsTry;
        }
    }

    public static void a(Context context, Location location) {
        if (location != null) {
            try {
                Editor editor = context.getSharedPreferences("LocationService", 0).edit();
                editor.putLong("lat", Double.doubleToRawLongBits(location.getLatitude()));
                editor.putLong("lng", Double.doubleToRawLongBits(location.getLongitude()));
                editor.putFloat("accuracy", location.getAccuracy());
                editor.putLong(Values.TIME, location.getTime());
                editor.commit();
            } catch (Exception e) {
                LoplatLogger.writeLog("[Exception] set location error: " + e);
            }
        }
    }

    public static Location b(Context context) {
        Location lastLocation = null;
        LocationManager locationManager = (LocationManager) context.getSystemService(Param.LOCATION);
        String provider = null;
        boolean isGPSEnabled = false;
        boolean isNetworkEnabled = false;
        if (locationManager != null) {
            try {
                isNetworkEnabled = locationManager.isProviderEnabled("network");
                isGPSEnabled = locationManager.isProviderEnabled("gps");
            } catch (Exception e) {
                LoplatLogger.writeLog("[Exception] get GPS provider error: " + e);
            }
        }
        if (isGPSEnabled || isNetworkEnabled) {
            if (isNetworkEnabled) {
                provider = "network";
            } else if (isGPSEnabled) {
                provider = "gps";
            }
        }
        if (provider != null) {
            try {
                if (VERSION.SDK_INT >= 23 && context.checkSelfPermission("android.permission.ACCESS_FINE_LOCATION") == -1 && context.checkSelfPermission("android.permission.ACCESS_COARSE_LOCATION") == -1) {
                    LoplatLogger.writeLog("location permission is denied");
                    return null;
                }
                lastLocation = locationManager.getLastKnownLocation(provider);
            } catch (Exception e2) {
                LoplatLogger.writeLog("[Exception] get a last location error: " + e2);
            }
        }
        return lastLocation;
    }
}