package com.igaworks.model;

public class ActivityCounter implements Comparable {
    private String activity;
    private int activityCounterNo;
    private int counter;
    private int day;
    private int dayUpdated;
    private String group;
    private int hour;
    private int hourUpdated;
    private int month;
    private int monthUpdated;
    private String noCountingUpdateDatetime;
    private String registDatetime;
    private String updateDatetime;
    private int year;
    private int yearUpdated;

    public ActivityCounter() {
    }

    public ActivityCounter(int activityCounterNo2, int year2, int month2, int day2, int hour2, String group2, String activity2, int counter2, int yearUpdated2, int monthUpdated2, int dayUpdated2, int hourUpdated2, String registDatetime2, String updateDatetime2, String noCountingUpdateDatetime2) {
        this.activityCounterNo = activityCounterNo2;
        this.year = year2;
        this.month = month2;
        this.day = day2;
        this.hour = hour2;
        this.group = group2;
        this.activity = activity2;
        this.counter = counter2;
        this.yearUpdated = yearUpdated2;
        this.monthUpdated = monthUpdated2;
        this.dayUpdated = dayUpdated2;
        this.hourUpdated = hourUpdated2;
        this.registDatetime = registDatetime2;
        this.updateDatetime = updateDatetime2;
        this.noCountingUpdateDatetime = noCountingUpdateDatetime2;
    }

    public String getNoCountingUpdateDatetime() {
        return this.noCountingUpdateDatetime;
    }

    public void setNoCountingUpdateDatetime(String noCountingUpdateDatetime2) {
        this.noCountingUpdateDatetime = noCountingUpdateDatetime2;
    }

    public int getActivityCounterNo() {
        return this.activityCounterNo;
    }

    public void setActivityCounterNo(int activityCounterNo2) {
        this.activityCounterNo = activityCounterNo2;
    }

    public int getYear() {
        return this.year;
    }

    public void setYear(int year2) {
        this.year = year2;
    }

    public int getMonth() {
        return this.month;
    }

    public void setMonth(int month2) {
        this.month = month2;
    }

    public int getDay() {
        return this.day;
    }

    public void setDay(int day2) {
        this.day = day2;
    }

    public int getHour() {
        return this.hour;
    }

    public void setHour(int hour2) {
        this.hour = hour2;
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

    public int getCounter() {
        return this.counter;
    }

    public void setCounter(int counter2) {
        this.counter = counter2;
    }

    public int getYearUpdated() {
        return this.yearUpdated;
    }

    public void setYearUpdated(int yearUpdated2) {
        this.yearUpdated = yearUpdated2;
    }

    public int getMonthUpdated() {
        return this.monthUpdated;
    }

    public void setMonthUpdated(int monthUpdated2) {
        this.monthUpdated = monthUpdated2;
    }

    public int getDayUpdated() {
        return this.dayUpdated;
    }

    public void setDayUpdated(int dayUpdated2) {
        this.dayUpdated = dayUpdated2;
    }

    public int getHourUpdated() {
        return this.hourUpdated;
    }

    public void setHourUpdated(int hourUpdated2) {
        this.hourUpdated = hourUpdated2;
    }

    public String getRegistDatetime() {
        return this.registDatetime;
    }

    public void setRegistDatetime(String registDatetime2) {
        this.registDatetime = registDatetime2;
    }

    public String getUpdateDatetime() {
        return this.updateDatetime;
    }

    public void setUpdateDatetime(String updateDatetime2) {
        this.updateDatetime = updateDatetime2;
    }

    public int compareTo(Object another) {
        try {
            ActivityCounter ac = (ActivityCounter) another;
            if (ac == null) {
                return -1;
            }
            if (this.year == ac.year && this.month == ac.month && this.day == ac.day && this.hour == ac.hour) {
                if (this.registDatetime.compareTo(ac.registDatetime) <= 0) {
                    return 1;
                }
                return -1;
            } else if (this.year > ac.getYear()) {
                return -1;
            } else {
                if (this.year == ac.year && this.month > ac.month) {
                    return -1;
                }
                if (this.year == ac.year && this.month == ac.month && this.day > ac.day) {
                    return -1;
                }
                if (this.year == ac.year && this.month == ac.month && this.day == ac.day && this.hour > ac.hour) {
                    return -1;
                }
                return 1;
            }
        } catch (Exception e) {
            return -1;
        }
    }
}