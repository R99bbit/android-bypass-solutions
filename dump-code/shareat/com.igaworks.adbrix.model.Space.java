package com.igaworks.adbrix.model;

import java.util.List;

public class Space {
    private List<Integer> CampaignList;
    private String SpaceKey;
    private List<SpaceSegment> SpaceSegments;

    public Space(String spaceKey, List<SpaceSegment> spaceSegments, List<Integer> campaignList) {
        this.SpaceKey = spaceKey;
        this.SpaceSegments = spaceSegments;
        this.CampaignList = campaignList;
    }

    public String getSpaceKey() {
        return this.SpaceKey;
    }

    public void setSpaceKey(String spaceKey) {
        this.SpaceKey = spaceKey;
    }

    public List<SpaceSegment> getSpaceSegments() {
        return this.SpaceSegments;
    }

    public void setSpaceSegments(List<SpaceSegment> spaceSegments) {
        this.SpaceSegments = spaceSegments;
    }

    public List<Integer> getCampaignList() {
        return this.CampaignList;
    }

    public void setCampaignList(List<Integer> campaignList) {
        this.CampaignList = campaignList;
    }
}