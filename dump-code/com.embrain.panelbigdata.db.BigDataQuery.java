package com.embrain.panelbigdata.db;

import android.provider.BaseColumns;

public final class BigDataQuery {

    public static final class TBAppList implements BaseColumns {
        public static final String APP_NAME = "app_name";
        public static final String APP_VER = "app_ver";
        public static final String[] COLUMNS = {"package_name", "app_name", "exec_time", LAST_UPDATE_TIME, FIRST_INSTALL_TIME, MARKET_PACKAGE, APP_VER};
        public static final String EXEC_TIME = "exec_time";
        public static final String FIRST_INSTALL_TIME = "first_install_time";
        public static final String LAST_UPDATE_TIME = "last_update_time";
        public static final String MARKET_PACKAGE = "market_package";
        public static final String PACKAGE_NAME = "package_name";
        public static final String _CREATE = "CREATE TABLE panel_app_list (package_name TEXT, app_name TEXT, exec_time NUMERIC, last_update_time NUMERIC, first_install_time  NUMERIC, market_package TEXT, app_ver TEXT );";
        public static final String _TABLE_NAME = "panel_app_list";
    }

    public static final class TBDeviceState implements BaseColumns {
        public static final String[] COLUMNS = {PUSH_RESP_DATE, USAGE_PERMISSION, USAGE_ALIVE_JOB, USAGE_AGREE, LOC_PERMISSION, LOC_ALIVE_JOB, LOC_AGREE, LOC_GPS_STATE, LOC_LOPLAT_STATUS, MESSAGE_ID};
        public static final String LOC_AGREE = "loc_agree";
        public static final String LOC_ALIVE_JOB = "loc_alive_job";
        public static final String LOC_GPS_STATE = "loc_gps_state";
        public static final String LOC_LOPLAT_STATUS = "loc_loplat_status";
        public static final String LOC_PERMISSION = "loc_permisssion";
        public static final String MESSAGE_ID = "message_id";
        public static final String PUSH_RESP_DATE = "push_resp_date";
        public static final String USAGE_AGREE = "usage_agree";
        public static final String USAGE_ALIVE_JOB = "usage_alive_job";
        public static final String USAGE_PERMISSION = "usage_permission";
        public static final String _CREATE = "CREATE TABLE device_state (push_resp_date NUMERIC, usage_permission INTEGER,usage_alive_job INTEGER, usage_agree INTEGER, loc_permisssion INTEGER, loc_alive_job INTEGER, loc_agree INTEGER, loc_gps_state INTEGER, loc_loplat_status INTEGER, message_id TEXT );";
        public static final String _TABLE_NAME = "device_state";
    }

    public static final class TBGpsState implements BaseColumns {
        public static final String[] COLUMNS = {EXEC_TIME, LAT, LNG, "gps_state"};
        public static final String EXEC_TIME = "create_time";
        public static final String GPS_STATE = "gps_state";
        public static final String LAT = "lat";
        public static final String LNG = "lng";
        public static final String _CREATE = "CREATE TABLE gps_state (create_time NUMERIC, lat REAL, lng REAL, gps_state INTEGER );";
        public static final String _TABLE_NAME = "gps_state";
    }

    public static final class TBUsage implements BaseColumns {
        public static final String APP_NAME = "app_name";
        public static final String[] COLUMNS = {"package_name", "app_name", "exec_time", TOTAL_USED_TIME, FIRST_TIME_STAMP, LAST_TIME_STAMP, LAST_USED_TIME_STAMP};
        public static final String EXEC_TIME = "exec_time";
        public static final String FIRST_TIME_STAMP = "first_time_stamp";
        public static final String LAST_TIME_STAMP = "last_time_stamp";
        public static final String LAST_USED_TIME_STAMP = "last_used_time_stamp";
        public static final String PACKAGE_NAME = "package_name";
        public static final String TOTAL_USED_TIME = "total_used_time";
        public static final String _CREATE = "CREATE TABLE panel_app_usage (package_name TEXT, app_name TEXT, exec_time NUMERIC, total_used_time INTEGER, first_time_stamp  NUMERIC, last_time_stamp NUMERIC, last_used_time_stamp NUMERIC );";
        public static final String _TABLE_NAME = "panel_app_usage";
    }
}