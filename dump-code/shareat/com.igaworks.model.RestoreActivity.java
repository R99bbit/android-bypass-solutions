package com.igaworks.model;

import java.util.Calendar;

public class RestoreActivity {
    private String activity;
    private String group;
    private int no;
    private Calendar registDatetime;

    public RestoreActivity() {
    }

    public RestoreActivity(int no2, String group2, String activity2, Calendar registDatetime2) {
        this.no = no2;
        this.group = group2;
        this.activity = activity2;
        this.registDatetime = registDatetime2;
    }

    public int getNo() {
        return this.no;
    }

    public void setNo(int no2) {
        this.no = no2;
    }

    public String getGroup() {
        return this.group;
    }

    public void setGroup(String group2) {
        this.group = group2;
    }

    public String getActivity() {
        return this.activity;
    }

    public void setActivity(String activity2) {
        this.activity = activity2;
    }

    public Calendar getRegistDatetime() {
        return this.registDatetime;
    }

    public void setRegistDatetime(Calendar registDatetime2) {
        this.registDatetime = registDatetime2;
    }
}