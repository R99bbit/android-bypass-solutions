package com.embrain.panelbigdata.usage;

import com.embrain.panelbigdata.Vo.BigdataCommon;
import com.embrain.panelbigdata.Vo.usage.UsageDao;
import com.embrain.panelbigdata.Vo.usage.UsageInsertRequest;
import java.util.ArrayList;
import java.util.List;

public class UsageInsertRequestExt extends UsageInsertRequest {
    public UsageInsertRequestExt(String str, String str2, String str3) {
        this.deviceInfo = new BigdataCommon(str);
        this.deviceInfo.ad_id = str2;
        this.token = str3;
        this.daily_usage_list = new ArrayList();
        this.app_list = new ArrayList();
    }

    public void setDailyUsageList(List<UsageDao> list) {
        this.daily_usage_list = list;
    }

    public void setAppList(List<ApplicationDao> list) {
        this.app_list = list;
    }
}