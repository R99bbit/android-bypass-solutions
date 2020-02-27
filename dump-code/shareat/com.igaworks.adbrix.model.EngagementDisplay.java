package com.igaworks.adbrix.model;

public class EngagementDisplay {
    private String CompleteMessage;
    private int CompleteToastmsec;
    private boolean IsProgressShow;
    private String ProgressMessage;
    private String ProgressTitle;

    public EngagementDisplay() {
    }

    public EngagementDisplay(boolean isProgressShow, String progressTitle, String progressMessage, String completeMessage, int completeToastMSec) {
        this.IsProgressShow = isProgressShow;
        this.ProgressTitle = progressTitle;
        this.ProgressMessage = progressMessage;
        this.CompleteMessage = completeMessage;
        this.CompleteToastmsec = completeToastMSec;
    }

    public boolean isProgressShow() {
        return this.IsProgressShow;
    }

    public void setProgressShow(boolean isProgressShow) {
        this.IsProgressShow = isProgressShow;
    }

    public String getProgressTitle() {
        return this.ProgressTitle;
    }

    public void setProgressTitle(String progressTitle) {
        this.ProgressTitle = progressTitle;
    }

    public String getProgressMessage() {
        return this.ProgressMessage;
    }

    public void setProgressMessage(String progressMessage) {
        this.ProgressMessage = progressMessage;
    }

    public String getCompleteMessage() {
        return this.CompleteMessage;
    }

    public void setCompleteMessage(String completeMessage) {
        this.CompleteMessage = completeMessage;
    }

    public int getCompleteToastMSec() {
        return this.CompleteToastmsec;
    }

    public void setCompleteToastMSec(int completeToastMSec) {
        this.CompleteToastmsec = completeToastMSec;
    }
}