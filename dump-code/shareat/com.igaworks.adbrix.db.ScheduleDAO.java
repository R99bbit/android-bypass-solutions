package com.igaworks.adbrix.db;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import com.igaworks.adbrix.json.JSON2ScheduleConverter;
import com.igaworks.adbrix.model.ScheduleContainer;

public class ScheduleDAO {
    public static final String SCHEDULE_SP_KEY = "saved_schedule";
    public static final String SCHEDULE_SP_NAME = "schedule_sp";
    private static ScheduleDAO singleton;
    private Editor scheduleEditor;
    private SharedPreferences scheduleSP;

    private ScheduleDAO() {
    }

    public static ScheduleDAO getInstance() {
        if (singleton == null) {
            singleton = new ScheduleDAO();
        }
        return singleton;
    }

    private SharedPreferences getSharedPreference(Context context) {
        if (this.scheduleSP == null) {
            this.scheduleSP = context.getSharedPreferences(SCHEDULE_SP_NAME, 0);
        }
        return this.scheduleSP;
    }

    private Editor getEditor(Context context) {
        if (this.scheduleEditor == null) {
            this.scheduleEditor = getSharedPreference(context).edit();
        }
        return this.scheduleEditor;
    }

    public void saveSchedule(Context context, String schedule) {
        getEditor(context).putString(SCHEDULE_SP_KEY, schedule);
        getEditor(context).commit();
    }

    public ScheduleContainer getSchedule(Context context) {
        return JSON2ScheduleConverter.json2ScheduleV2(context, getSharedPreference(context).getString(SCHEDULE_SP_KEY, null));
    }
}