package com.embrain.panelbigdata.location;

import android.content.Context;
import android.location.LocationManager;
import android.os.Build.VERSION;
import com.embrain.panelbigdata.EmBigDataManager;
import com.embrain.panelbigdata.Vo.location.LocationState;
import com.embrain.panelbigdata.utils.PrefUtils;

public class LocationStateExt extends LocationState {
    public LocationStateExt(Context context) {
        this.permission = hasPermission(context);
        this.aliveLocationJob = EmBigDataManager.aliveLocationJob();
        this.userAgree = PrefUtils.getUserAgreeLocation(context);
        this.gpsState = getGpsState(context);
        this.loplatState = LoplatManager.getStatus(context);
    }

    public static boolean canExecute(Context context) {
        return hasPermission(context) && PrefUtils.getUserAgreeLocation(context);
    }

    public static boolean hasPermission(Context context) {
        if (VERSION.SDK_INT < 23) {
            return true;
        }
        if (context.checkSelfPermission("android.permission.ACCESS_FINE_LOCATION") == 0 && context.checkSelfPermission("android.permission.ACCESS_COARSE_LOCATION") == 0) {
            return true;
        }
        return false;
    }

    public static boolean getGpsState(Context context) {
        return ((LocationManager) context.getSystemService("location")).isProviderEnabled("gps");
    }
}