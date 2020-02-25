package com.embrain.panelbigdata.location;

import android.content.Context;
import com.embrain.panelbigdata.utils.LogUtil;
import com.loplat.placeengine.Plengi;

public class LoplatManager {
    public static final String LOPLAT_CLIENT_ID = "embrain";
    public static final String LOPLAT_CLIENT_SECRET = "embrain2308";

    public static void initLoplatEngine(Context context, String str) {
        int init = Plengi.getInstance(context).init("embrain", "embrain2308", str);
        StringBuilder sb = new StringBuilder();
        sb.append("Loplat SDK init result : ");
        sb.append(init);
        LogUtil.write(sb.toString());
        setListener(context);
    }

    public static void setListener(Context context) {
        Plengi.getInstance(context).setListener(new EmbrainPlengiListener());
    }

    public static void start(Context context) {
        int start = Plengi.getInstance(context).start();
        StringBuilder sb = new StringBuilder();
        sb.append("Loplat SDK start result : ");
        sb.append(start);
        LogUtil.write(sb.toString());
        StringBuilder sb2 = new StringBuilder();
        sb2.append("Loplat SDK engine status : ");
        sb2.append(Plengi.getInstance(context).getEngineStatus());
        LogUtil.write(sb2.toString());
    }

    public static void stop(Context context) {
        Plengi.getInstance(context).stop();
    }

    public static int getStatus(Context context) {
        return Plengi.getInstance(context).getEngineStatus();
    }

    public static String getLoplatStatusString(int i) {
        if (i == -1) {
            return "NOT_INITIALIZED";
        }
        if (i == 0) {
            return "STOPPED";
        }
        if (i == 1) {
            return "STARTED";
        }
        if (i == 2) {
            return "STOPPED_TEMP";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("NOT DEFINED STATUS : ");
        sb.append(i);
        return sb.toString();
    }
}