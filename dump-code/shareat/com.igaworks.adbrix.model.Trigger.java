package com.igaworks.adbrix.model;

public class Trigger {
    private String Activity;
    private boolean Continue;
    private int Count;
    private String Group;
    private long Intervalmsec;
    private int ResetData;
    private String ResetType;

    public Trigger() {
        this.ResetData = -1;
    }

    public Trigger(String group, String activity, int count, long intervalMSec, boolean continuous, boolean isProgressShow, String progressTitle, String progressMessage, String resetType, int resetData, String completeMessage, int completeToastMSec) {
        this.Group = group;
        this.Activity = activity;
        this.Count = count;
        this.Intervalmsec = intervalMSec;
        this.Continue = continuous;
        this.ResetType = resetType;
        this.ResetData = resetData;
    }

    public String getResetType() {
        return this.ResetType;
    }

    public void setResetType(String resetType) {
        this.ResetType = resetType;
    }

    public int getResetData() {
        return this.ResetData;
    }

    public void setResetData(int resetData) {
        this.ResetData = resetData;
    }

    public String getGroup() {
        return this.Group;
    }

    public void setGroup(String group) {
        this.Group = group;
    }

    public String getActivity() {
        return this.Activity;
    }

    public void setActivity(String activity) {
        this.Activity = activity;
    }

    public int getCount() {
        return this.Count;
    }

    public void setCount(int count) {
        this.Count = count;
    }

    public long getIntervalMSec() {
        return this.Intervalmsec;
    }

    public void setIntervalMSec(long intervalHour) {
        this.Intervalmsec = intervalHour;
    }

    public boolean isContinuous() {
        return this.Continue;
    }

    public void setContinuous(boolean continuous) {
        this.Continue = continuous;
    }
}