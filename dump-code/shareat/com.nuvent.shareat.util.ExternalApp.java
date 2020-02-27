package com.nuvent.shareat.util;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.support.v4.app.FragmentActivity;
import com.nuvent.shareat.activity.BaseActivity;

public class ExternalApp {
    public static final String BAND = "com.nhn.android.band";
    public static final String EMAIL = "com.android.email";
    public static final String FACEBOOK = "com.facebook.katana";
    public static final String GMAIL = "com.google.android.gm";
    private static final String GOOGLE_PLAY = "https://play.google.com/store/apps/details?id=";
    public static final String INSTAGRAM = "com.instagram.android";
    public static final String KAKAOSTORY = "com.kakao.story";
    public static final String LINE = "jp.naver.line.android";
    public static final String NAVER_MAP = "com.nhn.android.nmap";

    public static boolean onInstallApp(final FragmentActivity act, int stringId, Intent intent, final String packageName) {
        if (!act.getPackageManager().queryIntentActivities(intent, 65536).isEmpty()) {
            return false;
        }
        ((BaseActivity) act).showConfirmDialog(act.getString(stringId), new Runnable() {
            public void run() {
                Intent mapIntent = new Intent("android.intent.action.VIEW", Uri.parse(ExternalApp.GOOGLE_PLAY + packageName));
                mapIntent.setPackage("com.android.vending");
                mapIntent.addFlags(268435456);
                act.startActivity(mapIntent);
            }
        });
        return true;
    }

    public static boolean onInstallApp(final Activity act, int stringId, Intent intent, final String packageName) {
        if (!act.getPackageManager().queryIntentActivities(intent, 65536).isEmpty()) {
            return false;
        }
        ((BaseActivity) act).showConfirmDialog(act.getString(stringId), new Runnable() {
            public void run() {
                Intent mapIntent = new Intent("android.intent.action.VIEW", Uri.parse(ExternalApp.GOOGLE_PLAY + packageName));
                mapIntent.setPackage("com.android.vending");
                mapIntent.addFlags(268435456);
                act.startActivity(mapIntent);
            }
        });
        return true;
    }
}