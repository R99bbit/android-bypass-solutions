package com.igaworks.adbrix.model;

public class Language {
    private String AlreadyParticipated;
    private String AnotherAppParticipate;
    private String CanNotParticipate;
    private String FirstUnitForOneStep;
    private String IsComplete;
    private String Mission;
    private String RewardUnitForOneStep;
    private String UnknownError;

    public Language() {
    }

    public Language(String canNotParticipate, String anotherAppParticipate, String unknownError, String alreadyParticipated, String firstUnitForOneStep, String rewardUnitForOneStep, String mission, String isComplete) {
        this.CanNotParticipate = canNotParticipate;
        this.AnotherAppParticipate = anotherAppParticipate;
        this.UnknownError = unknownError;
        this.AlreadyParticipated = alreadyParticipated;
        this.FirstUnitForOneStep = firstUnitForOneStep;
        this.RewardUnitForOneStep = rewardUnitForOneStep;
        this.Mission = mission;
        this.IsComplete = isComplete;
    }

    public String getCanNotParticipate() {
        if (this.CanNotParticipate == null) {
            this.CanNotParticipate = "\ucc38\uc5ec\ud560 \uc218 \uc5c6\ub294 \uad11\uace0\uc785\ub2c8\ub2e4.";
        }
        return this.CanNotParticipate;
    }

    public void setCanNotParticipate(String canNotParticipate) {
        this.CanNotParticipate = canNotParticipate;
    }

    public String getAnotherAppParticipate() {
        if (this.AnotherAppParticipate == null) {
            this.AnotherAppParticipate = "\ub2e4\ub978 \uc571\uc5d0\uc11c \ucc38\uc5ec \uc911\uc778 \uad11\uace0\uc785\ub2c8\ub2e4.";
        }
        return this.AnotherAppParticipate;
    }

    public void setAnotherAppParticipate(String anotherAppParticipate) {
        this.AnotherAppParticipate = anotherAppParticipate;
    }

    public String getUnknownError() {
        if (this.UnknownError == null) {
            this.UnknownError = "\uc8c4\uc1a1\ud569\ub2c8\ub2e4. \uc7a0\uc2dc \ud6c4 \ub2e4\uc2dc \uc2dc\ub3c4\ud574\uc8fc\uc138\uc694.";
        }
        return this.UnknownError;
    }

    public void setUnknownError(String unknownError) {
        this.UnknownError = unknownError;
    }

    public String getAlreadyParticipated() {
        if (this.AlreadyParticipated == null) {
            this.AlreadyParticipated = "\ucc38\uc5ec \uc644\ub8cc\ud55c \uad11\uace0\uc785\ub2c8\ub2e4.";
        }
        return this.AlreadyParticipated;
    }

    public void setAlreadyParticipated(String alreadyParticipated) {
        this.AlreadyParticipated = alreadyParticipated;
    }

    public String getFirstUnitForOneStep() {
        if (this.FirstUnitForOneStep == null) {
            this.FirstUnitForOneStep = "\uc124\uce58";
        }
        return this.FirstUnitForOneStep;
    }

    public void setFirstUnitForOneStep(String firstUnitForOneStep) {
        this.FirstUnitForOneStep = firstUnitForOneStep;
    }

    public String getRewardUnitForOneStep() {
        if (this.RewardUnitForOneStep == null) {
            this.RewardUnitForOneStep = "X";
        }
        return this.RewardUnitForOneStep;
    }

    public void setRewardUnitForOneStep(String rewardUnitForOneStep) {
        this.RewardUnitForOneStep = rewardUnitForOneStep;
    }

    public String getMission() {
        if (this.Mission == null) {
            this.Mission = "MISSION!";
        }
        return this.Mission;
    }

    public void setMission(String mission) {
        this.Mission = mission;
    }

    public String getIsComplete() {
        if (this.IsComplete == null) {
            this.IsComplete = "\ud68d\ub4dd";
        }
        return this.IsComplete;
    }

    public void setIsComplete(String isComplete) {
        this.IsComplete = isComplete;
    }
}