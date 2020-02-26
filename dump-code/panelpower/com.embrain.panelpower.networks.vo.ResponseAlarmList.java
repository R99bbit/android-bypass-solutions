package com.embrain.panelpower.networks.vo;

public class ResponseAlarmList {
    private static final String SUCCESS = "";
    public int noCnt;
    public String result;

    public boolean isSuccess() {
        return "success".equals(this.result);
    }

    public int alarmCnt() {
        return this.noCnt;
    }
}