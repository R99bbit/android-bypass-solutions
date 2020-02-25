package com.embrain.panelbigdata.Vo.usage;

import java.util.Date;

public class SendHistoryDao {
    public long SND_HIST_ID;
    public String ad_id;
    public Date execute_time;
    public String panel_id;
    public String reg_date;

    public String getPanel_id() {
        return this.panel_id;
    }

    public String getReg_date() {
        return this.reg_date;
    }

    public String getAd_id() {
        return this.ad_id;
    }

    public Date getExecute_time() {
        return this.execute_time;
    }

    public long getSND_HIST_ID() {
        return this.SND_HIST_ID;
    }

    public void setSND_HIST_ID(long j) {
        this.SND_HIST_ID = j;
    }
}