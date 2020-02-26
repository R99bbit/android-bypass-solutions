package com.loplat.placeengine;

import a.b.a.c.a;
import a.b.a.d.c;
import a.b.a.d.e;
import a.b.a.h;
import android.content.Context;
import android.net.wifi.ScanResult;
import android.os.SystemClock;
import androidx.annotation.RequiresApi;
import com.loplat.placeengine.cloud.RequestMessage.CellEntity;
import com.loplat.placeengine.cloud.RequestMessage.CellTowerInfo;
import com.loplat.placeengine.cloud.RequestMessage.CheckPlaceInfo;
import com.loplat.placeengine.wifi.WifiScanManager;
import com.loplat.placeengine.wifi.WifiType;
import java.util.List;

public class Plengi extends PlengiBase {
    public static Context mContext;
    public static Plengi mPlengi;

    public Plengi(Context context) {
        super(context);
        mContext = context;
    }

    public static synchronized Plengi getInstance(Context context) {
        Plengi plengi;
        synchronized (Plengi.class) {
            try {
                if (mPlengi == null && context != null) {
                    mPlengi = new Plengi(context.getApplicationContext());
                }
                plengi = mPlengi;
            }
        }
        return plengi;
    }

    public int checkPlaceForCook(CheckPlaceInfo checkPlaceInfo, OnPlengiListener onPlengiListener) {
        if (checkPlaceInfo == null) {
            return -1;
        }
        PlengiBase.mOnPlengiListener = onPlengiListener;
        return PlaceEngine.getPlaceInfoWithNewScanForCook(mContext, checkPlaceInfo);
    }

    public long getLastStartScanTime() {
        return a.b(mContext).m();
    }

    public int manual_lbs_request_foreground(OnPlengiListener onPlengiListener) {
        c b = c.b(mContext);
        CellTowerInfo b2 = a.b.a.g.a.b(b.k);
        if (b2 == null || b.n == null) {
            return -1;
        }
        int intValue = b2.getCellId().intValue();
        CellEntity cellEntity = new CellEntity();
        cellEntity.setCellId(b2.getCellId());
        cellEntity.setLac(b2.getLac());
        cellEntity.setDbm(b2.getDbm());
        cellEntity.setTime(SystemClock.elapsedRealtime());
        b.n.put(Integer.valueOf(intValue), cellEntity);
        b.a(b2, onPlengiListener);
        return 0;
    }

    public List<WifiType> searchPlaceForCook(String str, String str2, List<ScanResult> list, OnPlengiListener onPlengiListener) {
        h a2 = WifiScanManager.a(mContext, list, new h(0));
        e eVar = new e(mContext, 4, str, str2, a2.c, onPlengiListener);
        eVar.c();
        return a2.c;
    }

    public void setFingerPrintDataSource(int i) {
        PlaceEngineBase.setFpDataSource(mContext, i);
    }

    public void setMaxRss(int i) {
        WifiScanManager.a(i);
    }

    public void setMaxScannedAP(int i) {
        if (i > 0) {
            WifiScanManager.c = i;
        }
    }

    @RequiresApi(29)
    public void setScanOnlyWhileUsingTheApp(boolean z) {
        PlaceEngineBase.d = z;
    }

    public void setTimeLimit(long j) {
        WifiScanManager.f60a = j;
    }
}