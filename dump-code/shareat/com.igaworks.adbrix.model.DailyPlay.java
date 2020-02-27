package com.igaworks.adbrix.model;

public class DailyPlay {
    private int CampaignKey;
    private int ConversionKey;
    private int ParentConversionKey;
    private int PlayTime;

    public int getCampaignKey() {
        return this.CampaignKey;
    }

    public void setCampaignKey(int campaignKey) {
        this.CampaignKey = campaignKey;
    }

    public int getPlayTime() {
        return this.PlayTime;
    }

    public void setPlayTime(int playTime) {
        this.PlayTime = playTime;
    }

    public int getConversionKey() {
        return this.ConversionKey;
    }

    public void setConversionKey(int conversionKey) {
        this.ConversionKey = conversionKey;
    }

    public int getParentConversionKey() {
        return this.ParentConversionKey;
    }

    public void setParentConversionKey(int parentConversionKey) {
        this.ParentConversionKey = parentConversionKey;
    }

    public DailyPlay(int campaignKey, int playTime, int conversionKey, int parentConversionKey) {
        this.CampaignKey = campaignKey;
        this.PlayTime = playTime;
        this.ConversionKey = conversionKey;
        this.ParentConversionKey = parentConversionKey;
    }
}