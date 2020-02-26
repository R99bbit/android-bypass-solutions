package com.embrain.panelbigdata.usage;

import android.app.usage.UsageStats;
import com.embrain.panelbigdata.Vo.usage.UsageDao;

public class UsageDaoExt extends UsageDao {
    public UsageDaoExt(UsageStats usageStats) {
        this.package_name = usageStats.getPackageName();
        this.total_used_time = usageStats.getTotalTimeInForeground();
        this.first_time_stamp = usageStats.getFirstTimeStamp();
        this.last_time_stamp = usageStats.getLastTimeStamp();
        this.last_used_time_stamp = usageStats.getLastTimeUsed();
    }

    public void setAppName(String str) {
        this.app_name = str;
    }
}