package a.b.a.h;

import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.os.Build.VERSION;
import java.text.SimpleDateFormat;
import java.util.Date;

/* compiled from: PlengiMonitor */
public class d {

    /* compiled from: PlengiMonitor */
    public static class a {

        /* renamed from: a reason: collision with root package name */
        public int f46a;
        public String b;

        public a(int i, String str) {
            this.f46a = i;
            this.b = str;
        }
    }

    public static a a(Context context) {
        int i;
        String str = null;
        if (VERSION.SDK_INT >= 23) {
            UsageStatsManager usageStatsManager = (UsageStatsManager) context.getSystemService("usagestats");
            if (usageStatsManager != null) {
                try {
                    if (VERSION.SDK_INT >= 28) {
                        i = usageStatsManager.getAppStandbyBucket();
                    } else {
                        if (usageStatsManager.isAppInactive(context.getPackageName())) {
                            i = -1;
                        }
                        i = 10;
                    }
                } catch (Exception unused) {
                }
                if (i == -1) {
                    str = "[inactive]";
                } else if (i == 5) {
                    str = "[whitelist]";
                } else if (i == 10) {
                    str = "[active]";
                } else if (i == 20) {
                    str = "[working_set]";
                } else if (i == 30) {
                    str = "[frequent]";
                } else if (i == 40) {
                    str = "[rare]";
                }
            } else {
                i = 10;
            }
        } else {
            i = 0;
        }
        return new a(i, str);
    }

    public static String a(long j) {
        return new SimpleDateFormat("MM-dd HH:mm:ss").format(new Date(j));
    }
}