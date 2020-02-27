package com.nuvent.shareat.manager;

import android.content.Context;
import android.location.Criteria;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Bundle;
import com.google.firebase.analytics.FirebaseAnalytics.Param;
import com.nuvent.shareat.ShareatApp;
import java.util.Observable;

public class GpsManager implements LocationListener {
    public static final double DEFAULTLAT = 37.4986366d;
    public static final double DEFAULTLON = 127.027021d;
    private static final long MIN_DISTANCE_CHANGE_FOR_UPDATES = 10;
    private static final long MIN_TIME_BW_UPDATES = 60000;
    boolean isGPSEnabled = false;
    boolean isGetLocation = false;
    boolean isNetworkEnabled = false;
    private final Context mContext;
    private GpsObserver mGpsObserver;
    double mLatitude = 37.4986366d;
    private Location mLocation;
    protected LocationManager mLocationManager;
    double mLongitude = 127.027021d;

    public class GpsObserver extends Observable {
        public GpsObserver() {
        }

        public void onChangePlaceName(Object data) {
            setChanged();
            notifyObservers(data);
        }
    }

    public GpsManager(Context context) {
        this.mContext = context;
        getLocation(true);
    }

    public void stopGPSListener() {
        if (this.mLocationManager != null) {
            this.mLocationManager.removeUpdates(this);
        }
    }

    public void startGPSListener() {
        try {
            ShareatApp.getInstance();
            if (!ShareatApp.isEmulator()) {
                this.mLocationManager.requestLocationUpdates("network", MIN_TIME_BW_UPDATES, 10.0f, this);
            }
            this.mLocationManager.requestLocationUpdates("gps", MIN_TIME_BW_UPDATES, 10.0f, this);
        } catch (SecurityException e) {
            e.printStackTrace();
        }
    }

    public void getLocation(boolean isAlert) {
        if (this.mLocationManager != null) {
            this.mLocationManager.removeUpdates(this);
        }
        if (this.mLocationManager == null) {
            this.mLocationManager = (LocationManager) this.mContext.getSystemService(Param.LOCATION);
        }
        Criteria criteria = new Criteria();
        criteria.setAccuracy(1);
        criteria.setPowerRequirement(1);
        criteria.setAltitudeRequired(false);
        criteria.setCostAllowed(false);
        boolean isNetworkEnabled2 = false;
        boolean isGPSEnabled2 = this.mLocationManager.isProviderEnabled("gps");
        ShareatApp.getInstance();
        if (!ShareatApp.isEmulator()) {
            isNetworkEnabled2 = this.mLocationManager.isProviderEnabled("network");
        }
        startGPSListener();
        if (isGPSEnabled2 || isNetworkEnabled2) {
            try {
                this.isGetLocation = true;
                if (isNetworkEnabled2 && this.mLocation == null && this.mLocationManager != null) {
                    this.mLocation = this.mLocationManager.getLastKnownLocation("network");
                    if (this.mLocation != null) {
                        this.mLatitude = this.mLocation.getLatitude();
                        this.mLongitude = this.mLocation.getLongitude();
                    }
                }
                if (isGPSEnabled2 && this.mLocation == null && this.mLocationManager != null) {
                    this.mLocation = this.mLocationManager.getLastKnownLocation("gps");
                    if (this.mLocation != null) {
                        this.mLatitude = this.mLocation.getLatitude();
                        this.mLongitude = this.mLocation.getLongitude();
                    }
                }
            } catch (SecurityException e) {
                e.printStackTrace();
            }
        } else {
            this.isGetLocation = false;
        }
        if (this.mLocation == null) {
            this.isGetLocation = false;
            if (isAlert) {
                showSettingsAlert();
            }
        }
        searchLocationName(this.mLocation);
    }

    public double getLatitude() {
        if (this.mLocation != null) {
            this.mLatitude = this.mLocation.getLatitude();
        }
        return this.mLatitude;
    }

    public double getLongitude() {
        if (this.mLocation != null) {
            this.mLongitude = this.mLocation.getLongitude();
        }
        return this.mLongitude;
    }

    public boolean isGetLocation() {
        return this.isGetLocation;
    }

    public void showSettingsAlert() {
        ShareatApp.getInstance().showGpsAlert();
    }

    public void onLocationChanged(Location location) {
        if (location != null) {
            this.mLocation = location;
            this.mLatitude = location.getLatitude();
            this.mLongitude = location.getLongitude();
            this.isGetLocation = true;
        }
        searchLocationName(location);
    }

    public void onStatusChanged(String provider, int status, Bundle extras) {
    }

    public void onProviderEnabled(String provider) {
        getLocation(false);
    }

    public void onProviderDisabled(String provider) {
        this.mLocation = null;
        this.isGetLocation = false;
        this.mLatitude = 37.4986366d;
        this.mLongitude = 127.027021d;
        searchLocationName(this.mLocation);
    }

    public GpsObserver getGpsObserver() {
        if (this.mGpsObserver == null) {
            this.mGpsObserver = new GpsObserver();
        }
        return this.mGpsObserver;
    }

    private void searchLocationName(Location location) {
        if (location != null) {
            double lon = location.getLongitude();
            double lat = location.getLatitude();
        }
    }

    public void ondestory() {
    }
}