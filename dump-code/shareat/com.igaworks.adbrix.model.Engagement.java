package com.igaworks.adbrix.model;

import java.util.List;

public class Engagement {
    private boolean AllowDuplication;
    private int ConversionKey;
    private EngagementDisplay Display;
    private int ParentConversionKey;
    private List<Segment> Segments;
    private Trigger Trigger;

    public Engagement() {
    }

    public Engagement(List<Segment> segments, Trigger trigger, EngagementDisplay displayData, int conversionKey, int parentConversionKey, boolean allowDuplication) {
        this.Segments = segments;
        this.Trigger = trigger;
        this.Display = displayData;
        this.ConversionKey = conversionKey;
        this.ParentConversionKey = parentConversionKey;
        this.AllowDuplication = allowDuplication;
    }

    public void setSegments(List<Segment> segments) {
        this.Segments = segments;
    }

    public List<Segment> getSegments() {
        return this.Segments;
    }

    public void setConditions(List<Segment> segments) {
        this.Segments = segments;
    }

    public Trigger getTrigger() {
        return this.Trigger;
    }

    public void setTrigger(Trigger trigger) {
        this.Trigger = trigger;
    }

    public EngagementDisplay getDisplayData() {
        return this.Display;
    }

    public void setDisplayData(EngagementDisplay displayData) {
        this.Display = displayData;
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

    public boolean isAllowDuplication() {
        return this.AllowDuplication;
    }

    public void setAllowDuplication(boolean allowDuplication) {
        this.AllowDuplication = allowDuplication;
    }

    public String toString() {
        String tr = "";
        if (this.Trigger != null) {
            tr = new StringBuilder(String.valueOf(this.Trigger.getGroup())).append("/").append(this.Trigger.getActivity()).toString();
        }
        return String.format("ParentConversionKey : %d, ConversionKey : %d, Trigger : %s", new Object[]{Integer.valueOf(this.ParentConversionKey), Integer.valueOf(this.ConversionKey), tr});
    }
}