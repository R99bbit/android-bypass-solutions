package com.igaworks.core;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.provider.Settings.Secure;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

public class OpenUDID_manager implements ServiceConnection {
    private static final boolean LOG = true;
    /* access modifiers changed from: private */
    public static String OpenUDID = null;
    public static final String PREFS_NAME = "openudid_prefs";
    public static final String PREF_KEY = "openudid";
    public static final String TAG = "OpenUDID";
    /* access modifiers changed from: private */
    public static boolean mInitialized = false;
    private final Context mContext;
    /* access modifiers changed from: private */
    public List<ResolveInfo> mMatchingIntents;
    /* access modifiers changed from: private */
    public final SharedPreferences mPreferences;
    private final Random mRandom;
    /* access modifiers changed from: private */
    public Map<String, Integer> mReceivedOpenUDIDs;

    private class ValueComparator implements Comparator {
        private ValueComparator() {
        }

        /* synthetic */ ValueComparator(OpenUDID_manager openUDID_manager, ValueComparator valueComparator) {
            this();
        }

        public int compare(Object a, Object b) {
            if (((Integer) OpenUDID_manager.this.mReceivedOpenUDIDs.get(a)).intValue() < ((Integer) OpenUDID_manager.this.mReceivedOpenUDIDs.get(b)).intValue()) {
                return 1;
            }
            if (OpenUDID_manager.this.mReceivedOpenUDIDs.get(a) == OpenUDID_manager.this.mReceivedOpenUDIDs.get(b)) {
                return 0;
            }
            return -1;
        }
    }

    private OpenUDID_manager(Context context) {
        this.mPreferences = context.getSharedPreferences(PREFS_NAME, 0);
        this.mContext = context;
        this.mRandom = new Random();
        this.mReceivedOpenUDIDs = new HashMap();
    }

    /* synthetic */ OpenUDID_manager(Context context, OpenUDID_manager openUDID_manager) {
        this(context);
    }

    public void onServiceConnected(ComponentName className, IBinder service) {
        try {
            Parcel data = Parcel.obtain();
            data.writeInt(this.mRandom.nextInt());
            Parcel reply = Parcel.obtain();
            service.transact(1, Parcel.obtain(), reply, 0);
            if (data.readInt() == reply.readInt()) {
                String _openUDID = reply.readString();
                if (_openUDID != null) {
                    if (this.mReceivedOpenUDIDs.containsKey(_openUDID)) {
                        this.mReceivedOpenUDIDs.put(_openUDID, Integer.valueOf(this.mReceivedOpenUDIDs.get(_openUDID).intValue() + 1));
                    } else {
                        this.mReceivedOpenUDIDs.put(_openUDID, Integer.valueOf(1));
                    }
                }
            }
        } catch (RemoteException e) {
        }
        try {
            this.mContext.unbindService(this);
            startService();
        } catch (Exception e2) {
        }
    }

    public void onServiceDisconnected(ComponentName className) {
    }

    private void storeOpenUDID() {
        new Thread(new Runnable() {
            public void run() {
                Editor e = OpenUDID_manager.this.mPreferences.edit();
                e.putString(OpenUDID_manager.PREF_KEY, OpenUDID_manager.OpenUDID);
                e.commit();
            }
        }).start();
    }

    private void generateOpenUDID() {
        OpenUDID = Secure.getString(this.mContext.getContentResolver(), RequestParameter.ANDROID_ID);
        if (OpenUDID == null || OpenUDID.equals("9774d56d682e549c") || OpenUDID.length() < 15) {
            OpenUDID = new BigInteger(64, new SecureRandom()).toString(16);
        }
    }

    /* access modifiers changed from: private */
    public void startService() {
        try {
            if (this.mMatchingIntents.size() > 0) {
                ServiceInfo servInfo = this.mMatchingIntents.get(0).serviceInfo;
                Intent i = new Intent();
                i.setComponent(new ComponentName(servInfo.applicationInfo.packageName, servInfo.name));
                this.mMatchingIntents.clear();
                this.mContext.bindService(i, this, 1);
                return;
            }
            getMostFrequentOpenUDID();
            if (OpenUDID == null) {
                generateOpenUDID();
            }
            storeOpenUDID();
            mInitialized = true;
        } catch (Exception e) {
            startService();
        }
    }

    private void getMostFrequentOpenUDID() {
        if (!this.mReceivedOpenUDIDs.isEmpty()) {
            TreeMap<String, Integer> sorted_OpenUDIDS = new TreeMap<>(new ValueComparator(this, null));
            sorted_OpenUDIDS.putAll(this.mReceivedOpenUDIDs);
            OpenUDID = sorted_OpenUDIDS.firstKey();
        }
    }

    public static String getOpenUDID() {
        return OpenUDID;
    }

    public static boolean isInitialized() {
        return mInitialized;
    }

    public static void sync(final Context context) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    OpenUDID_manager manager = new OpenUDID_manager(context, null);
                    OpenUDID_manager.OpenUDID = manager.mPreferences.getString(OpenUDID_manager.PREF_KEY, null);
                    if (OpenUDID_manager.OpenUDID == null) {
                        manager.mMatchingIntents = context.getPackageManager().queryIntentServices(new Intent("org.OpenUDID.GETUDID"), 0);
                        if (manager.mMatchingIntents != null) {
                            manager.startService();
                            return;
                        }
                        return;
                    }
                    OpenUDID_manager.mInitialized = true;
                } catch (Exception e) {
                }
            }
        });
    }
}