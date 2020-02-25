package me.leolin.shortcutbadger;

import android.app.Notification;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.os.Build;
import android.util.Log;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import me.leolin.shortcutbadger.impl.AdwHomeBadger;
import me.leolin.shortcutbadger.impl.ApexHomeBadger;
import me.leolin.shortcutbadger.impl.AsusHomeBadger;
import me.leolin.shortcutbadger.impl.DefaultBadger;
import me.leolin.shortcutbadger.impl.EverythingMeHomeBadger;
import me.leolin.shortcutbadger.impl.HuaweiHomeBadger;
import me.leolin.shortcutbadger.impl.NewHtcHomeBadger;
import me.leolin.shortcutbadger.impl.NovaHomeBadger;
import me.leolin.shortcutbadger.impl.OPPOHomeBader;
import me.leolin.shortcutbadger.impl.SamsungHomeBadger;
import me.leolin.shortcutbadger.impl.SonyHomeBadger;
import me.leolin.shortcutbadger.impl.VivoHomeBadger;
import me.leolin.shortcutbadger.impl.ZTEHomeBadger;
import me.leolin.shortcutbadger.impl.ZukHomeBadger;

public final class ShortcutBadger {
    private static final List<Class<? extends Badger>> BADGERS = new LinkedList();
    private static final String LOG_TAG = "ShortcutBadger";
    private static final int SUPPORTED_CHECK_ATTEMPTS = 3;
    private static ComponentName sComponentName;
    private static final Object sCounterSupportedLock = new Object();
    private static volatile Boolean sIsBadgeCounterSupported;
    private static Badger sShortcutBadger;

    static {
        BADGERS.add(AdwHomeBadger.class);
        BADGERS.add(ApexHomeBadger.class);
        BADGERS.add(DefaultBadger.class);
        BADGERS.add(NewHtcHomeBadger.class);
        BADGERS.add(NovaHomeBadger.class);
        BADGERS.add(SonyHomeBadger.class);
        BADGERS.add(AsusHomeBadger.class);
        BADGERS.add(HuaweiHomeBadger.class);
        BADGERS.add(OPPOHomeBader.class);
        BADGERS.add(SamsungHomeBadger.class);
        BADGERS.add(ZukHomeBadger.class);
        BADGERS.add(VivoHomeBadger.class);
        BADGERS.add(ZTEHomeBadger.class);
        BADGERS.add(EverythingMeHomeBadger.class);
    }

    public static boolean applyCount(Context context, int i) {
        try {
            applyCountOrThrow(context, i);
            return true;
        } catch (ShortcutBadgeException e) {
            if (Log.isLoggable(LOG_TAG, 3)) {
                Log.d(LOG_TAG, "Unable to execute badge", e);
            }
            return false;
        }
    }

    public static void applyCountOrThrow(Context context, int i) throws ShortcutBadgeException {
        if (sShortcutBadger != null || initBadger(context)) {
            try {
                sShortcutBadger.executeBadge(context, sComponentName, i);
            } catch (Exception e) {
                throw new ShortcutBadgeException("Unable to execute badge", e);
            }
        } else {
            throw new ShortcutBadgeException("No default launcher available");
        }
    }

    public static boolean removeCount(Context context) {
        return applyCount(context, 0);
    }

    public static void removeCountOrThrow(Context context) throws ShortcutBadgeException {
        applyCountOrThrow(context, 0);
    }

    public static boolean isBadgeCounterSupported(Context context) {
        if (sIsBadgeCounterSupported == null) {
            synchronized (sCounterSupportedLock) {
                if (sIsBadgeCounterSupported == null) {
                    String str = null;
                    int i = 0;
                    while (true) {
                        if (i >= 3) {
                            break;
                        }
                        try {
                            StringBuilder sb = new StringBuilder();
                            sb.append("Checking if platform supports badge counters, attempt ");
                            sb.append(String.format("%d/%d.", new Object[]{Integer.valueOf(i + 1), Integer.valueOf(3)}));
                            Log.i(LOG_TAG, sb.toString());
                            if (initBadger(context)) {
                                sShortcutBadger.executeBadge(context, sComponentName, 0);
                                sIsBadgeCounterSupported = Boolean.valueOf(true);
                                Log.i(LOG_TAG, "Badge counter is supported in this platform.");
                                break;
                            }
                            str = "Failed to initialize the badge counter.";
                            i++;
                        } catch (Exception e) {
                            str = e.getMessage();
                        }
                    }
                    if (sIsBadgeCounterSupported == null) {
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("Badge counter seems not supported for this platform: ");
                        sb2.append(str);
                        Log.w(LOG_TAG, sb2.toString());
                        sIsBadgeCounterSupported = Boolean.valueOf(false);
                    }
                }
            }
        }
        return sIsBadgeCounterSupported.booleanValue();
    }

    public static void applyNotification(Context context, Notification notification, int i) {
        if (Build.MANUFACTURER.equalsIgnoreCase("Xiaomi")) {
            try {
                Object obj = notification.getClass().getDeclaredField("extraNotification").get(notification);
                obj.getClass().getDeclaredMethod("setMessageCount", new Class[]{Integer.TYPE}).invoke(obj, new Object[]{Integer.valueOf(i)});
            } catch (Exception e) {
                if (Log.isLoggable(LOG_TAG, 3)) {
                    Log.d(LOG_TAG, "Unable to execute badge", e);
                }
            }
        }
    }

    private static boolean initBadger(Context context) {
        Badger badger;
        Intent launchIntentForPackage = context.getPackageManager().getLaunchIntentForPackage(context.getPackageName());
        if (launchIntentForPackage == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("Unable to find launch intent for package ");
            sb.append(context.getPackageName());
            Log.e(LOG_TAG, sb.toString());
            return false;
        }
        sComponentName = launchIntentForPackage.getComponent();
        Intent intent = new Intent("android.intent.action.MAIN");
        intent.addCategory("android.intent.category.HOME");
        for (ResolveInfo resolveInfo : context.getPackageManager().queryIntentActivities(intent, 65536)) {
            String str = resolveInfo.activityInfo.packageName;
            Iterator<Class<? extends Badger>> it = BADGERS.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                try {
                    badger = (Badger) it.next().newInstance();
                } catch (Exception unused) {
                    badger = null;
                }
                if (badger != null && badger.getSupportLaunchers().contains(str)) {
                    sShortcutBadger = badger;
                    break;
                }
            }
            if (sShortcutBadger != null) {
                break;
            }
        }
        if (sShortcutBadger == null) {
            if (Build.MANUFACTURER.equalsIgnoreCase("ZUK")) {
                sShortcutBadger = new ZukHomeBadger();
            } else if (Build.MANUFACTURER.equalsIgnoreCase("OPPO")) {
                sShortcutBadger = new OPPOHomeBader();
            } else if (Build.MANUFACTURER.equalsIgnoreCase("VIVO")) {
                sShortcutBadger = new VivoHomeBadger();
            } else if (Build.MANUFACTURER.equalsIgnoreCase("ZTE")) {
                sShortcutBadger = new ZTEHomeBadger();
            } else {
                sShortcutBadger = new DefaultBadger();
            }
        }
        return true;
    }

    private ShortcutBadger() {
    }
}