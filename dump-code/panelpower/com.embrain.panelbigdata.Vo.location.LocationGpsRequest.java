package com.embrain.panelbigdata.Vo.location;

import android.content.Context;
import com.embrain.panelbigdata.Vo.BigdataCommon;
import com.embrain.panelbigdata.Vo.EmBasicRequest;
import com.embrain.panelbigdata.utils.PrefUtils;

public class LocationGpsRequest extends EmBasicRequest {
    public BigdataCommon deviceInfo;
    public long execute_time;
    public boolean gps_state;
    public double lat;
    public double lng;

    public LocationGpsRequest(Context context) {
        this.deviceInfo = new BigdataCommon(PrefUtils.getPanelId(context));
        this.deviceInfo.ad_id = PrefUtils.getGoogleADID(context);
    }

    public void setExecTime(long j) {
        this.execute_time = j;
    }
}