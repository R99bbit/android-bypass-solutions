package com.embrain.panelbigdata.Vo.usage;

public class UsageState {
    public boolean aliveUsageJob;
    public boolean permission;
    public boolean userAgree;

    public UsageState() {
    }

    public UsageState(int i, int i2, int i3) {
        boolean z = false;
        this.permission = i == 1;
        this.aliveUsageJob = i2 == 1;
        this.userAgree = i3 == 1 ? true : z;
    }

    public boolean isPermission() {
        return this.permission;
    }

    public void setPermission(boolean z) {
        this.permission = z;
    }

    public boolean isAliveUsageJob() {
        return this.aliveUsageJob;
    }

    public void setAliveUsageJob(boolean z) {
        this.aliveUsageJob = z;
    }

    public boolean isUserAgree() {
        return this.userAgree;
    }

    public void setUserAgree(boolean z) {
        this.userAgree = z;
    }
}