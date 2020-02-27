package com.nuvent.shareat.model;

import java.util.ArrayList;

public class NotificationResultModel extends BaseResultModel {
    private ArrayList<NotificationModel> result_list;

    public class NotifyRequest extends JsonConvertable {
        private ArrayList<NotificationModel> list;

        public NotifyRequest(ArrayList<NotificationModel> list2) {
            this.list = list2;
        }
    }

    public ArrayList<NotificationModel> getResult_list() {
        if (this.result_list == null) {
            this.result_list = new ArrayList<>();
        }
        return this.result_list;
    }

    public void setResult_list(ArrayList<NotificationModel> result_list2) {
        this.result_list = result_list2;
    }

    public String getRequestParam() {
        return new NotifyRequest(this.result_list).toJson();
    }
}