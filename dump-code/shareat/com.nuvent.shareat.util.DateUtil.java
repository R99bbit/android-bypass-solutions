package com.nuvent.shareat.util;

import com.nuvent.shareat.model.store.StoreInstaModel;
import io.fabric.sdk.android.services.events.EventsFilesManager;
import java.text.SimpleDateFormat;
import java.util.Calendar;

public class DateUtil {
    private static final int DAY = 86400;
    private static final int HOUR = 3600;
    private static final int MINUTE = 60;

    public static String[] getEventTime(float time) {
        StringBuilder sb = new StringBuilder();
        int termEventInt = (int) time;
        if (termEventInt < 60) {
            try {
                sb.append(termEventInt + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR);
                sb.append("\ucd08\uc804");
            } catch (Exception e) {
            }
        } else if (termEventInt < 3600) {
            sb.append(Math.round((float) (termEventInt / 60)) + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR);
            sb.append("\ubd84\uc804");
        } else if (termEventInt < DAY) {
            sb.append(Math.round((float) (termEventInt / 3600)) + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR);
            sb.append("\uc2dc\uac04\uc804");
        } else {
            sb.append(Math.round((float) (termEventInt / DAY)) + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR);
            sb.append("\uc77c\uc804");
        }
        return sb.toString().split(EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR);
    }

    public static String getToday() {
        String[] week = {"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"};
        String dayStr = new SimpleDateFormat(StoreInstaModel.MESSAGE_CARD_TIME_FORMAT).format(Long.valueOf(System.currentTimeMillis()));
        return dayStr + ". " + week[Calendar.getInstance().get(7) - 1].toUpperCase();
    }
}