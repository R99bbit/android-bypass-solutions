package com.igaworks.model;

import java.util.List;

public class ParticipationProgressResponseModel {
    private List<ParticipationProgressModel> Data;
    private boolean Result;
    private int ResultCode;
    private String ResultMessage;

    public ParticipationProgressResponseModel() {
    }

    public ParticipationProgressResponseModel(boolean result, int resultCode, String resultMessage, List<ParticipationProgressModel> data) {
        this.Result = result;
        this.ResultCode = resultCode;
        this.ResultMessage = resultMessage;
        this.Data = data;
    }

    public boolean isResult() {
        return this.Result;
    }

    public void setResult(boolean result) {
        this.Result = result;
    }

    public int getResultCode() {
        return this.ResultCode;
    }

    public void setResultCode(int resultCode) {
        this.ResultCode = resultCode;
    }

    public String getResultMessage() {
        return this.ResultMessage;
    }

    public void setResultMessage(String resultMessage) {
        this.ResultMessage = resultMessage;
    }

    public List<ParticipationProgressModel> getData() {
        return this.Data;
    }

    public void setData(List<ParticipationProgressModel> data) {
        this.Data = data;
    }
}