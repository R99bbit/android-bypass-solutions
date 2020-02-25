package org.acra.util;

import android.content.Context;
import android.util.Log;
import android.widget.Toast;
import org.acra.ACRA;

public final class ToastSender {
    public static void sendToast(Context context, int i, int i2) {
        try {
            Toast.makeText(context, i, i2).show();
        } catch (RuntimeException e) {
            Log.e(ACRA.LOG_TAG, "Could not send crash Toast", e);
        }
    }
}