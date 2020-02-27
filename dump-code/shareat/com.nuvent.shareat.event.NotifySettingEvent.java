package com.nuvent.shareat.event;

import com.nuvent.shareat.model.NotificationModel;
import com.nuvent.shareat.model.NotificationResultModel;
import java.util.Iterator;

public class NotifySettingEvent {
    private NotificationResultModel mNotificationModel = null;

    public NotifySettingEvent(NotificationResultModel nm) {
        this.mNotificationModel = nm;
    }

    public NotificationResultModel getNotificationModel() {
        return this.mNotificationModel;
    }

    public String getAutoBranchSearch() {
        Iterator<NotificationModel> it = this.mNotificationModel.getResult_list().iterator();
        while (it.hasNext()) {
            NotificationModel notifyModel = it.next();
            if (notifyModel.getNotice_id().equals("90")) {
                return notifyModel.getUse_yn();
            }
        }
        return "Y";
    }
}