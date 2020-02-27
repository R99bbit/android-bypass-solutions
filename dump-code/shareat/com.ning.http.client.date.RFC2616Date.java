package com.ning.http.client.date;

public final class RFC2616Date {
    private final int dayOfMonth;
    private final int hour;
    private final int minute;
    private final int month;
    private final int second;
    private final int year;

    public static final class Builder {
        private int dayOfMonth;
        private int hour;
        private int minute;
        private int month;
        private int second;
        private int year;

        public void setDayOfMonth(int dayOfMonth2) {
            this.dayOfMonth = dayOfMonth2;
        }

        public void setJanuary() {
            this.month = 1;
        }

        public void setFebruary() {
            this.month = 2;
        }

        public void setMarch() {
            this.month = 3;
        }

        public void setApril() {
            this.month = 4;
        }

        public void setMay() {
            this.month = 5;
        }

        public void setJune() {
            this.month = 6;
        }

        public void setJuly() {
            this.month = 7;
        }

        public void setAugust() {
            this.month = 8;
        }

        public void setSeptember() {
            this.month = 9;
        }

        public void setOctobre() {
            this.month = 10;
        }

        public void setNovembre() {
            this.month = 11;
        }

        public void setDecember() {
            this.month = 12;
        }

        public void setYear(int year2) {
            this.year = year2;
        }

        public void setHour(int hour2) {
            this.hour = hour2;
        }

        public void setMinute(int minute2) {
            this.minute = minute2;
        }

        public void setSecond(int second2) {
            this.second = second2;
        }

        public RFC2616Date build() {
            return new RFC2616Date(this.year, this.month, this.dayOfMonth, this.hour, this.minute, this.second);
        }
    }

    public RFC2616Date(int year2, int month2, int dayOfMonth2, int hour2, int minute2, int second2) {
        this.year = year2;
        this.month = month2;
        this.dayOfMonth = dayOfMonth2;
        this.hour = hour2;
        this.minute = minute2;
        this.second = second2;
    }

    public int year() {
        return this.year;
    }

    public int month() {
        return this.month;
    }

    public int dayOfMonth() {
        return this.dayOfMonth;
    }

    public int hour() {
        return this.hour;
    }

    public int minute() {
        return this.minute;
    }

    public int second() {
        return this.second;
    }
}