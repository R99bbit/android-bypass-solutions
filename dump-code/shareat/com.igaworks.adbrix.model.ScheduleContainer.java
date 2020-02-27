package com.igaworks.adbrix.model;

public class ScheduleContainer {
    private String CheckSum;
    private Schedule Schedule;

    public ScheduleContainer(Schedule schedule, String checkSum) {
        this.Schedule = schedule;
        this.CheckSum = checkSum;
    }

    public Schedule getSchedule() {
        return this.Schedule;
    }

    public void setSchedule(Schedule schedule) {
        this.Schedule = schedule;
    }

    public String getCheckSum() {
        return this.CheckSum;
    }

    public void setCheckSum(String checkSum) {
        this.CheckSum = checkSum;
    }
}