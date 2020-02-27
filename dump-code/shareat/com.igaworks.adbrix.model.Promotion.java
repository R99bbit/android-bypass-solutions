package com.igaworks.adbrix.model;

import java.util.List;

public class Promotion {
    private int CampaignKey;
    private int CampaignType;
    private PromotionDisplay Display;
    private boolean IsFilterAlreadyInstalled;
    private List<Segment> Segments;
    private String TargetAppScheme;
    private boolean isVisible;

    public Promotion() {
    }

    public Promotion(int CampaignType2, int CampaignKey2, List<Segment> Segments2, PromotionDisplay Display2, String TargetAppScheme2, boolean IsFilterAlreadyInstalled2) {
        this.CampaignType = CampaignType2;
        this.CampaignKey = CampaignKey2;
        this.Segments = Segments2;
        this.Display = Display2;
        this.TargetAppScheme = TargetAppScheme2;
        this.IsFilterAlreadyInstalled = IsFilterAlreadyInstalled2;
    }

    public boolean isVisible() {
        return this.isVisible;
    }

    public void setVisible(boolean isVisible2) {
        this.isVisible = isVisible2;
    }

    public int getCampaignType() {
        return this.CampaignType;
    }

    public void setCampaignType(int campaignType) {
        this.CampaignType = campaignType;
    }

    public int getCampaignKey() {
        return this.CampaignKey;
    }

    public void setCampaignKey(int campaignKey) {
        this.CampaignKey = campaignKey;
    }

    public List<Segment> getSegments() {
        return this.Segments;
    }

    public void setSegments(List<Segment> segments) {
        this.Segments = segments;
    }

    public PromotionDisplay getDisplay() {
        return this.Display;
    }

    public void setDisplay(PromotionDisplay display) {
        this.Display = display;
    }

    public String getTargetAppScheme() {
        return this.TargetAppScheme;
    }

    public void setTargetAppScheme(String targetAppScheme) {
        this.TargetAppScheme = targetAppScheme;
    }

    public boolean isIsFilterAlreadyInstalled() {
        return this.IsFilterAlreadyInstalled;
    }

    public void setIsFilterAlreadyInstalled(boolean isFilterAlreadyInstalled) {
        this.IsFilterAlreadyInstalled = isFilterAlreadyInstalled;
    }
}