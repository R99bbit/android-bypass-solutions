package com.embrain.panelbigdata.Vo.location;

public class LocationState {
    public boolean aliveLocationJob;
    public boolean gpsState;
    public int loplatState;
    public boolean permission;
    public boolean userAgree;

    public LocationState() {
    }

    public LocationState(int i, int i2, int i3, int i4, int i5) {
        boolean z = false;
        this.permission = i == 1;
        this.aliveLocationJob = i2 == 1;
        this.userAgree = i3 == 1;
        this.gpsState = i4 == 1 ? true : z;
        this.loplatState = i5;
    }

    public boolean isPermission() {
        return this.permission;
    }

    public void setPermission(boolean z) {
        this.permission = z;
    }

    public boolean isAliveLocationJob() {
        return this.aliveLocationJob;
    }

    public void setAliveLocationJob(boolean z) {
        this.aliveLocationJob = z;
    }

    public boolean isUserAgree() {
        return this.userAgree;
    }

    public void setUserAgree(boolean z) {
        this.userAgree = z;
    }

    public boolean isGpsState() {
        return this.gpsState;
    }

    public void setGpsState(boolean z) {
        this.gpsState = z;
    }

    public int getLoplatState() {
        return this.loplatState;
    }

    public void setLoplatState(int i) {
        this.loplatState = i;
    }
}