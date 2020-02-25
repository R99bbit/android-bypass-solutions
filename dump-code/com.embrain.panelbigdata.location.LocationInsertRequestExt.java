package com.embrain.panelbigdata.location;

import com.embrain.panelbigdata.Vo.BigdataCommon;
import com.embrain.panelbigdata.Vo.location.LocationInsertRequest;
import com.loplat.placeengine.PlengiResponse;

public class LocationInsertRequestExt extends LocationInsertRequest {
    public LocationInsertRequestExt(String str, String str2) {
        this.device_info = new BigdataCommon(str);
        this.device_info.ad_id = str2;
    }

    public void setLoplatObj(PlengiResponse plengiResponse) {
        this.loplat_obj = plengiResponse;
    }
}