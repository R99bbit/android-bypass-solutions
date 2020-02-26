package com.loplat.placeengine;

import a.b.a.c.a;
import android.content.Context;
import com.loplat.placeengine.cloud.RequestMessage.CheckPlaceInfo;

public class PlaceEngine extends PlaceEngineBase {
    public static int getPlaceInfoWithNewScanForCook(Context context, CheckPlaceInfo checkPlaceInfo) {
        if (PlaceEngineBase.getEngineStatus(context) == 2) {
            return -1;
        }
        a.b(context).h = checkPlaceInfo;
        return PlaceEngineBase.startWiFiScan(context, 4);
    }
}