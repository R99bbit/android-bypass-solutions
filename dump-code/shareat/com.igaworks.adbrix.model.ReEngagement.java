package com.igaworks.adbrix.model;

import java.util.List;

public class ReEngagement {
    private List<DailyPlay> DailyPlay;

    public List<DailyPlay> getDailyPlay() {
        return this.DailyPlay;
    }

    public void setDailyPlay(List<DailyPlay> dailyPlay) {
        this.DailyPlay = dailyPlay;
    }

    public ReEngagement() {
    }

    public ReEngagement(List<DailyPlay> dailyPlay) {
        this.DailyPlay = dailyPlay;
    }
}