package com.igaworks.adbrix.model;

public class RealRewardResultModel {
    private String FailMsg;
    private boolean Result;
    private int ResultCode;
    private String ResultMessage;
    private String RewardImage;
    private String RewardName;
    private int RewardQuantity;
    private long SessionNo;
    private int StatusCodes;
    private String SuccessMsg;
    private String type;

    public RealRewardResultModel() {
    }

    public RealRewardResultModel(boolean result, int resultCode, String resultMessage, String successMsg, String failMsg, String rewardName, int rewardQuantity, String rewardImage, long sessionNo, int statusCodes, String type2) {
        this.Result = result;
        this.ResultCode = resultCode;
        this.ResultMessage = resultMessage;
        this.SuccessMsg = successMsg;
        this.FailMsg = failMsg;
        this.RewardName = rewardName;
        this.RewardQuantity = rewardQuantity;
        this.RewardImage = rewardImage;
        this.SessionNo = sessionNo;
        this.StatusCodes = statusCodes;
        this.type = type2;
    }

    public int getStatusCodes() {
        return this.StatusCodes;
    }

    public void setStatusCodes(int statusCodes) {
        this.StatusCodes = statusCodes;
    }

    public String getFailMsg() {
        return this.FailMsg;
    }

    public void setFailMsg(String failMsg) {
        this.FailMsg = failMsg;
    }

    public String getRewardName() {
        return this.RewardName;
    }

    public void setRewardName(String rewardName) {
        this.RewardName = rewardName;
    }

    public int getRewardQuantity() {
        return this.RewardQuantity;
    }

    public void setRewardQuantity(int rewardQuantity) {
        this.RewardQuantity = rewardQuantity;
    }

    public String getRewardImage() {
        return this.RewardImage;
    }

    public void setRewardImage(String rewardImage) {
        this.RewardImage = rewardImage;
    }

    public String getType() {
        return this.type;
    }

    public void setType(String type2) {
        this.type = type2;
    }

    public String getSuccessMsg() {
        return this.SuccessMsg;
    }

    public void setSuccessMsg(String successMsg) {
        this.SuccessMsg = successMsg;
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

    public long getSessionNo() {
        return this.SessionNo;
    }

    public void setSessionNo(long sessionNo) {
        this.SessionNo = sessionNo;
    }
}