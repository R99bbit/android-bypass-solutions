package com.embrain.panelbigdata.Vo.location;

import com.embrain.panelbigdata.Vo.BigdataCommon;
import com.embrain.panelbigdata.Vo.EmBasicRequest;
import com.loplat.placeengine.PlengiResponse;

public class LocationInsertRequest extends EmBasicRequest {
    public BigdataCommon device_info;
    public PlengiResponse loplat_obj;
}