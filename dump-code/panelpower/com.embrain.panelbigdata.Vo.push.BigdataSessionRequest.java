package com.embrain.panelbigdata.Vo.push;

import com.embrain.panelbigdata.Vo.BigdataCommon;
import com.embrain.panelbigdata.Vo.EmBasicRequest;
import com.embrain.panelbigdata.Vo.location.LocationState;
import com.embrain.panelbigdata.Vo.usage.UsageState;

public class BigdataSessionRequest extends EmBasicRequest {
    public BigdataCommon deviceInfo;
    public LocationState locationState;
    public String messageId;
    public long push_resp_date;
    public UsageState usageState;

    public BigdataCommon getDeviceInfo() {
        return this.deviceInfo;
    }

    public void setDeviceInfo(BigdataCommon bigdataCommon) {
        this.deviceInfo = bigdataCommon;
    }

    public UsageState getUsageState() {
        return this.usageState;
    }

    public void setUsageState(UsageState usageState2) {
        this.usageState = usageState2;
    }

    public LocationState getLocationState() {
        return this.locationState;
    }

    public void setLocationState(LocationState locationState2) {
        this.locationState = locationState2;
    }

    public String getMessageId() {
        return this.messageId;
    }

    public void setMessageId(String str) {
        this.messageId = str;
    }

    public void setExecTime(long j) {
        this.push_resp_date = j;
    }
}