package com.igaworks.core;

import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;

public class OpenUDID_service extends Service {
    public IBinder onBind(Intent arg0) {
        return new Binder() {
            public boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
                SharedPreferences preferences = OpenUDID_service.this.getSharedPreferences(OpenUDID_manager.PREFS_NAME, 0);
                reply.writeInt(data.readInt());
                reply.writeString(preferences.getString(OpenUDID_manager.PREF_KEY, null));
                return true;
            }
        };
    }
}