package com.embrain.panelbigdata.Vo.usage;

import com.embrain.panelbigdata.Vo.BigdataCommon;
import com.embrain.panelbigdata.Vo.EmBasicRequest;
import com.embrain.panelbigdata.usage.ApplicationDao;
import java.util.List;

public class UsageInsertRequest extends EmBasicRequest {
    public List<ApplicationDao> app_list;
    public List<UsageDao> daily_usage_list;
    public BigdataCommon deviceInfo;
    public long endTime;
    public String token;

    public List<UsageDao> getDailyUsageList() {
        return this.daily_usage_list;
    }

    public List<ApplicationDao> getAppList() {
        return this.app_list;
    }
}