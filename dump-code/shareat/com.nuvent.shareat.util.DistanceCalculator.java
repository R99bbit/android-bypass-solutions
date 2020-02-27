package com.nuvent.shareat.util;

import android.location.Location;

public class DistanceCalculator {
    private static int LIMIT_DISTANCE = 500;

    public static boolean isOverDistance(double lat1, double lng1, double lat2, double lng2) {
        Location saveLocation = new Location("saveLocation");
        Location currentLocation = new Location("currentLocation");
        saveLocation.setLatitude(lat1);
        saveLocation.setLongitude(lng1);
        currentLocation.setLatitude(lat2);
        currentLocation.setLongitude(lng2);
        return ((double) LIMIT_DISTANCE) < ((double) saveLocation.distanceTo(currentLocation));
    }
}