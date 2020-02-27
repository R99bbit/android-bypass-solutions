package com.igaworks.adbrix.model;

import java.util.List;

public class Schedule {
    private List<Engagement> Engagement;
    private Media Media;
    private List<Promotion> Promotion;
    private ReEngagement ReEngagement;
    private List<RealReward> RealRewards;
    private List<Space> Space;
    private List<ViralCPIModel> ViralCPIs;

    public Schedule() {
    }

    public Schedule(List<RealReward> realRewards, List<Engagement> engagement, ReEngagement reEngagement, List<Promotion> promotion, List<Space> space, Media media, List<ViralCPIModel> viralCPIs) {
        this.RealRewards = realRewards;
        this.Engagement = engagement;
        this.ReEngagement = reEngagement;
        this.Promotion = promotion;
        this.Space = space;
        this.Media = media;
        this.ViralCPIs = viralCPIs;
    }

    public List<RealReward> getRealRewards() {
        return this.RealRewards;
    }

    public void setRealRewards(List<RealReward> realRewards) {
        this.RealRewards = realRewards;
    }

    public List<Engagement> getEngagements() {
        return this.Engagement;
    }

    public void setEngagements(List<Engagement> engagements) {
        this.Engagement = engagements;
    }

    public List<Promotion> getPromotions() {
        return this.Promotion;
    }

    public void setPromotions(List<Promotion> promotions) {
        this.Promotion = promotions;
    }

    public List<Space> getSpaces() {
        return this.Space;
    }

    public void setSpaces(List<Space> spaces) {
        this.Space = spaces;
    }

    public Media getMedia() {
        return this.Media;
    }

    public void setMedia(Media media) {
        this.Media = media;
    }

    public List<ViralCPIModel> getViralCPIs() {
        return this.ViralCPIs;
    }

    public void setViralCPIs(List<ViralCPIModel> viralCPIs) {
        this.ViralCPIs = viralCPIs;
    }

    public ReEngagement getReEngagement() {
        return this.ReEngagement;
    }

    public void setReEngagement(ReEngagement reEngagement) {
        this.ReEngagement = reEngagement;
    }
}