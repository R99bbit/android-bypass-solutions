package org.acra.util;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.util.Log;
import org.acra.ACRA;

public final class PackageManagerWrapper {
    private final Context context;

    public PackageManagerWrapper(Context context2) {
        this.context = context2;
    }

    public boolean hasPermission(String str) {
        PackageManager packageManager = this.context.getPackageManager();
        boolean z = false;
        if (packageManager == null) {
            return false;
        }
        try {
            if (packageManager.checkPermission(str, this.context.getPackageName()) == 0) {
                z = true;
            }
        } catch (RuntimeException unused) {
        }
        return z;
    }

    public PackageInfo getPackageInfo() {
        PackageManager packageManager = this.context.getPackageManager();
        if (packageManager == null) {
            return null;
        }
        try {
            return packageManager.getPackageInfo(this.context.getPackageName(), 0);
        } catch (NameNotFoundException unused) {
            String str = ACRA.LOG_TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("Failed to find PackageInfo for current App : ");
            sb.append(this.context.getPackageName());
            Log.v(str, sb.toString());
            return null;
        } catch (RuntimeException unused2) {
            return null;
        }
    }
}