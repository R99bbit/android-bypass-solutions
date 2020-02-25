package com.embrain.panelpower.utils;

import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.widget.Toast;
import com.embrain.panelbigdata.utils.StringUtils;

public class OtherPackageUtils {
    private static final String PKG_MAP_DAUM = "net.daum.android.map";
    private static final String PKG_MAP_GOOGLE = "com.google.android.apps.maps";
    private static final String PKG_MAP_NAVER = "com.nhn.android.nmap";

    public static void goBrowser(Context context, String str) {
        try {
            Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(str));
            intent.setFlags(268435456);
            context.startActivity(intent);
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(context, "\uc678\ubd80 \ube0c\ub77c\uc6b0\uc838\ub85c \uc5f0\uacb0 \ud560 \uc218 \uc5c6\uc2b5\ub2c8\ub2e4.", 0).show();
        }
    }

    public static void goMap(Context context, double d, double d2, String str) {
        goMap(context, PKG_MAP_DAUM, d, d2, str);
    }

    public static void goMap(Context context, String str, double d, double d2, String str2) {
        Intent intent = new Intent("android.intent.action.VIEW");
        if (StringUtils.isEmpty(str2)) {
            intent.setData(Uri.parse(String.format("geo:%s,%s", new Object[]{Double.valueOf(d), Double.valueOf(d2)})));
        } else {
            intent.setData(Uri.parse(String.format("geo:%s,%s?q=%s", new Object[]{Double.valueOf(d), Double.valueOf(d2), str2})));
        }
        if (!StringUtils.isEmpty(str)) {
            intent.setPackage(str);
        }
        try {
            context.startActivity(intent);
        } catch (ActivityNotFoundException e) {
            e.printStackTrace();
            Toast.makeText(context, "\uc678\ubd80 \ube0c\ub77c\uc6b0\uc838\ub85c \uc5f0\uacb0 \ud560 \uc218 \uc5c6\uc2b5\ub2c8\ub2e4.", 0).show();
        }
    }
}