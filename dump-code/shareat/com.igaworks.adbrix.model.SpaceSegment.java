package com.igaworks.adbrix.model;

import java.util.List;

public class SpaceSegment {
    private int CampaignType;
    private List<Segment> Segments;

    public SpaceSegment() {
    }

    public SpaceSegment(int campaignType, List<Segment> segments) {
        this.CampaignType = campaignType;
        this.Segments = segments;
    }

    public int getCampaignType() {
        return this.CampaignType;
    }

    public void setCampaignType(int campaignType) {
        this.CampaignType = campaignType;
    }

    public List<Segment> getSegments() {
        return this.Segments;
    }

    public void setSegments(List<Segment> segments) {
        this.Segments = segments;
    }
}