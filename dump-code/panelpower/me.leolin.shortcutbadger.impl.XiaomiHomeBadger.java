package me.leolin.shortcutbadger.impl;

import android.annotation.TargetApi;
import android.app.Notification;
import android.app.Notification.Builder;
import android.app.NotificationManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.os.Build;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import me.leolin.shortcutbadger.Badger;
import me.leolin.shortcutbadger.ShortcutBadgeException;
import me.leolin.shortcutbadger.util.BroadcastHelper;

@Deprecated
public class XiaomiHomeBadger implements Badger {
    public static final String EXTRA_UPDATE_APP_COMPONENT_NAME = "android.intent.extra.update_application_component_name";
    public static final String EXTRA_UPDATE_APP_MSG_TEXT = "android.intent.extra.update_application_message_text";
    public static final String INTENT_ACTION = "android.intent.action.APPLICATION_MESSAGE_UPDATE";
    private ResolveInfo resolveInfo;

    /* JADX WARNING: Can't wrap try/catch for region: R(2:8|9) */
    /* JADX WARNING: Code restructure failed: missing block: B:9:?, code lost:
        r2.set(r1, java.lang.Integer.valueOf(r7));
     */
    /* JADX WARNING: Missing exception handler attribute for start block: B:8:0x002a */
    public void executeBadge(Context context, ComponentName componentName, int i) throws ShortcutBadgeException {
        Object obj;
        Object obj2 = "";
        try {
            Object newInstance = Class.forName("android.app.MiuiNotification").newInstance();
            Field declaredField = newInstance.getClass().getDeclaredField("messageCount");
            declaredField.setAccessible(true);
            if (i == 0) {
                obj = obj2;
            } else {
                obj = Integer.valueOf(i);
            }
            declaredField.set(newInstance, String.valueOf(obj));
        } catch (Exception unused) {
            Intent intent = new Intent(INTENT_ACTION);
            StringBuilder sb = new StringBuilder();
            sb.append(componentName.getPackageName());
            sb.append("/");
            sb.append(componentName.getClassName());
            intent.putExtra(EXTRA_UPDATE_APP_COMPONENT_NAME, sb.toString());
            if (i != 0) {
                obj2 = Integer.valueOf(i);
            }
            intent.putExtra(EXTRA_UPDATE_APP_MSG_TEXT, String.valueOf(obj2));
            if (BroadcastHelper.canResolveBroadcast(context, intent)) {
                context.sendBroadcast(intent);
            }
        }
        if (Build.MANUFACTURER.equalsIgnoreCase("Xiaomi")) {
            tryNewMiuiBadge(context, i);
        }
    }

    @TargetApi(16)
    private void tryNewMiuiBadge(Context context, int i) throws ShortcutBadgeException {
        if (this.resolveInfo == null) {
            Intent intent = new Intent("android.intent.action.MAIN");
            intent.addCategory("android.intent.category.HOME");
            this.resolveInfo = context.getPackageManager().resolveActivity(intent, 65536);
        }
        if (this.resolveInfo != null) {
            NotificationManager notificationManager = (NotificationManager) context.getSystemService("notification");
            Notification build = new Builder(context).setContentTitle("").setContentText("").setSmallIcon(this.resolveInfo.getIconResource()).build();
            try {
                Object obj = build.getClass().getDeclaredField("extraNotification").get(build);
                obj.getClass().getDeclaredMethod("setMessageCount", new Class[]{Integer.TYPE}).invoke(obj, new Object[]{Integer.valueOf(i)});
                notificationManager.notify(0, build);
            } catch (Exception e) {
                throw new ShortcutBadgeException("not able to set badge", e);
            }
        }
    }

    public List<String> getSupportLaunchers() {
        return Arrays.asList(new String[]{"com.miui.miuilite", "com.miui.home", "com.miui.miuihome", "com.miui.miuihome2", "com.miui.mihome", "com.miui.mihome2", "com.i.miui.launcher"});
    }
}