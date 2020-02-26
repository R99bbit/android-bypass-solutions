package me.leolin.shortcutbadger.impl;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import java.util.Arrays;
import java.util.List;
import me.leolin.shortcutbadger.Badger;
import me.leolin.shortcutbadger.ShortcutBadgeException;
import me.leolin.shortcutbadger.util.BroadcastHelper;

public class NewHtcHomeBadger implements Badger {
    public static final String COUNT = "count";
    public static final String EXTRA_COMPONENT = "com.htc.launcher.extra.COMPONENT";
    public static final String EXTRA_COUNT = "com.htc.launcher.extra.COUNT";
    public static final String INTENT_SET_NOTIFICATION = "com.htc.launcher.action.SET_NOTIFICATION";
    public static final String INTENT_UPDATE_SHORTCUT = "com.htc.launcher.action.UPDATE_SHORTCUT";
    public static final String PACKAGENAME = "packagename";

    public void executeBadge(Context context, ComponentName componentName, int i) throws ShortcutBadgeException {
        Intent intent = new Intent(INTENT_SET_NOTIFICATION);
        intent.putExtra(EXTRA_COMPONENT, componentName.flattenToShortString());
        intent.putExtra(EXTRA_COUNT, i);
        Intent intent2 = new Intent(INTENT_UPDATE_SHORTCUT);
        intent2.putExtra(PACKAGENAME, componentName.getPackageName());
        intent2.putExtra(COUNT, i);
        if (BroadcastHelper.canResolveBroadcast(context, intent) || BroadcastHelper.canResolveBroadcast(context, intent2)) {
            context.sendBroadcast(intent);
            context.sendBroadcast(intent2);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("unable to resolve intent: ");
        sb.append(intent2.toString());
        throw new ShortcutBadgeException(sb.toString());
    }

    public List<String> getSupportLaunchers() {
        return Arrays.asList(new String[]{"com.htc.launcher"});
    }
}