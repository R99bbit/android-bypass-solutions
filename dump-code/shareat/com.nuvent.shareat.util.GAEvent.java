package com.nuvent.shareat.util;

import android.app.Activity;
import android.content.Context;
import android.text.TextUtils;
import com.google.android.gms.analytics.HitBuilders.EventBuilder;
import com.google.android.gms.analytics.HitBuilders.ScreenViewBuilder;
import com.google.android.gms.analytics.HitBuilders.TimingBuilder;
import com.google.android.gms.analytics.Tracker;
import com.igaworks.adbrix.IgawAdbrix;
import com.nuvent.shareat.BuildConfig;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.ShareatApp.TrackerName;
import java.util.HashMap;
import java.util.Map;

public class GAEvent {
    public static void onGaEvent(Activity act, int categoryId, int actionId, int labelId) {
        if (act != null) {
            ShareatApp.getInstance().getTracker(TrackerName.APP_TRACKER).send(new EventBuilder().setCategory(act.getString(categoryId)).setAction(act.getString(actionId)).setLabel(act.getString(labelId)).build());
        }
    }

    public static void onGaEvent(Activity act, int categoryId, int actionId, String label) {
        if (act != null) {
            ShareatApp.getInstance().getTracker(TrackerName.APP_TRACKER).send(new EventBuilder().setCategory(act.getString(categoryId)).setAction(act.getString(actionId)).setLabel(label).build());
        }
    }

    public static void onGaEventSendParams(Map<String, String> params) {
        ShareatApp.getInstance().getTracker(TrackerName.APP_TRACKER).send(params);
    }

    public static void onGaEvent(String categoryId, String actionId, String labelId) {
        ShareatApp.getInstance().getTracker(TrackerName.APP_TRACKER).send(new EventBuilder().setCategory(categoryId).setAction(actionId).setLabel(labelId).build());
    }

    public static void onGaEvent(Activity act, int categoryId, int actionId, int labelId, String tag) {
        ShareatApp.getInstance().getTracker(TrackerName.APP_TRACKER).send(new EventBuilder().setCategory(act.getString(categoryId)).setAction(act.getString(actionId) + "\n" + tag).setLabel(act.getString(labelId)).build());
    }

    public static void onUserSignIn(Context context, String userSno) {
        if (BuildConfig.FLAVOR.equals("develop")) {
            String string = context.getResources().getString(R.string.ga_trackingId_d);
        } else {
            String string2 = context.getResources().getString(R.string.ga_trackingId);
        }
        Tracker t = ShareatApp.getInstance().getTracker(TrackerName.APP_TRACKER);
        t.set("&uid", userSno);
        t.send(new EventBuilder().setCategory("UX").setAction("User Sign In").build());
    }

    public static void onUserTimings(Activity act, int categoryId, long value, int nameId, int labelId) {
        if (15000 < value) {
            onGaEvent(act, (int) R.string.error, (int) R.string.ga_ev_app_speed, (int) R.string.max_timeout);
            return;
        }
        try {
            ShareatApp.getInstance().getTracker(TrackerName.APP_TRACKER).send(new TimingBuilder().setCategory(act.getString(categoryId)).setValue(value).setVariable(act.getString(nameId)).setLabel(act.getString(labelId)).build());
        } catch (Exception e) {
            e.printStackTrace();
            onGaEvent(act, (int) R.string.error, (int) R.string.ga_ev_app_speed, (int) R.string.max_timeout);
        }
    }

    public static void onUserTimings(String categoryId, long value, String nameId, String labelId) {
        if (15000 < value) {
            onGaEvent("\uc624\ub958", "\uc571\uc18d\ub3c4", "Max_Timeout");
            return;
        }
        try {
            ShareatApp.getInstance().getTracker(TrackerName.APP_TRACKER).send(new TimingBuilder().setCategory(categoryId).setValue(value).setVariable(nameId).setLabel(labelId).build());
        } catch (Exception e) {
            e.printStackTrace();
            onGaEvent("\uc624\ub958", "\uc571\uc18d\ub3c4", "Max_Timeout");
        }
    }

    public static void sessionCustomDimensions(String screenName, String value) {
        Map<Integer, String> dimensions = new HashMap<>();
        dimensions.put(Integer.valueOf(11), value);
        onGACustomDimensions(null, screenName, dimensions);
    }

    public static void onGACustomDimensions(Activity act, String screenName, Map<Integer, String> dimensions) {
        try {
            Tracker tracker = ShareatApp.getInstance().getTracker(TrackerName.APP_TRACKER);
            tracker.setScreenName(screenName);
            ScreenViewBuilder screenViewBuilder = new ScreenViewBuilder();
            for (Integer key : dimensions.keySet()) {
                String value = dimensions.get(key);
                if (!TextUtils.isEmpty(value)) {
                    screenViewBuilder.setCustomDimension(key.intValue(), value);
                }
            }
            tracker.send(screenViewBuilder.build());
        } catch (Exception e) {
        }
    }

    public static void onGAScreenView(Activity act, int screenId) {
        Tracker tracker = ShareatApp.getInstance().getTracker(TrackerName.APP_TRACKER);
        tracker.setScreenName(act.getString(screenId));
        tracker.send(new ScreenViewBuilder().build());
        IgawAdbrix.retention(act.getString(screenId));
    }

    public static void onGAScreenViewNewSession(Activity act, int screenId) {
        Tracker tracker = ShareatApp.getInstance().getTracker(TrackerName.APP_TRACKER);
        tracker.setScreenName(act.getString(screenId));
        tracker.send(((ScreenViewBuilder) new ScreenViewBuilder().setNewSession()).build());
    }
}