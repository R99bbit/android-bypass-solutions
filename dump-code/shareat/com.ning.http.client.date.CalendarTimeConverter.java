package com.ning.http.client.date;

import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;

public class CalendarTimeConverter implements TimeConverter {
    public static final TimeZone GMT = TimeZone.getTimeZone("GMT");

    public long toTime(RFC2616Date dateElements) {
        Calendar calendar = new GregorianCalendar(dateElements.year(), dateElements.month() - 1, dateElements.dayOfMonth(), dateElements.hour(), dateElements.minute(), dateElements.second());
        calendar.setTimeZone(GMT);
        return calendar.getTimeInMillis();
    }
}