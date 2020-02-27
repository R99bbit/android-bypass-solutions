package com.igaworks.adbrix.model;

public class RealReward {
    private int ConversionKey;
    private boolean IsDailyEvent;
    private boolean IsTest;
    private String MissionText;
    private boolean NoCondition;
    private long ProgressValidTime;
    private String RealRewardImageUrl;
    private int RealRewardKey;
    private String RealRewardName;

    public RealReward() {
    }

    public RealReward(String realRewardName, String realRewardImageUrl, String missionText, int realRewardKey, long progressValidTime, boolean isTest, int conversionKey, boolean isDailyEvent, boolean noCondition) {
        this.RealRewardName = realRewardName;
        this.RealRewardImageUrl = realRewardImageUrl;
        this.MissionText = missionText;
        this.RealRewardKey = realRewardKey;
        this.ProgressValidTime = progressValidTime;
        this.IsTest = isTest;
        this.ConversionKey = conversionKey;
        this.IsDailyEvent = isDailyEvent;
        this.NoCondition = noCondition;
    }

    public boolean isIsDailyEvent() {
        return this.IsDailyEvent;
    }

    public void setIsDailyEvent(boolean isDailyEvent) {
        this.IsDailyEvent = isDailyEvent;
    }

    public boolean isNoCondition() {
        return this.NoCondition;
    }

    public void setNoCondition(boolean noCondition) {
        this.NoCondition = noCondition;
    }

    public boolean isIsTest() {
        return this.IsTest;
    }

    public void setIsTest(boolean isTest) {
        this.IsTest = isTest;
    }

    public int getConversionKey() {
        return this.ConversionKey;
    }

    public void setConversionKey(int conversionKey) {
        this.ConversionKey = conversionKey;
    }

    public String getRealRewardName() {
        return this.RealRewardName;
    }

    public void setRealRewardName(String realRewardName) {
        this.RealRewardName = realRewardName;
    }

    public String getRealRewardImageUrl() {
        return this.RealRewardImageUrl;
    }

    public void setRealRewardImageUrl(String realRewardImageUrl) {
        this.RealRewardImageUrl = realRewardImageUrl;
    }

    public String getMissionText() {
        return this.MissionText;
    }

    public void setMissionText(String missionText) {
        this.MissionText = missionText;
    }

    public int getRealRewardKey() {
        return this.RealRewardKey;
    }

    public void setRealRewardKey(int realRewardKey) {
        this.RealRewardKey = realRewardKey;
    }

    public long getProgressValidTime() {
        return this.ProgressValidTime;
    }

    public void setProgressValidTime(long progressValidTime) {
        this.ProgressValidTime = progressValidTime;
    }
}