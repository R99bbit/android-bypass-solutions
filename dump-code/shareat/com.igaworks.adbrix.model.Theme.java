package com.igaworks.adbrix.model;

import com.igaworks.adbrix.util.CPEConstant;

public class Theme {
    private String CirclePlayBtn;
    private String CloseBtn;
    private String FirstUnitBGColorForOneStep;
    private String MissionCheckOff;
    private String MissionCheckOn;
    private String PlayBtnAreaBG;
    private String RewardUnitBGColorForOneStep;
    private String SecondUnitBGColorForOneStep;
    private String SelectedAppArrow;
    private String SlideLeftBtn;
    private String SlideRightBtn;
    private String SquarePlayBtn;
    private String StepArrow;

    public Theme() {
    }

    public Theme(String circlePlayBtn, String squarePlayBtn, String missionCheckOff, String missionCheckOn, String playBtnAreaBG, String slideLeftBtn, String slideRightBtn, String stepArrow, String closeBtn, String selectedAppArrow, String firstUnitBGColorForOneStep, String secondUnitBGColorForOneStep, String rewardUnitBGColorForOneStep) {
        this.CirclePlayBtn = circlePlayBtn;
        this.SquarePlayBtn = squarePlayBtn;
        this.MissionCheckOff = missionCheckOff;
        this.MissionCheckOn = missionCheckOn;
        this.PlayBtnAreaBG = playBtnAreaBG;
        this.SlideLeftBtn = slideLeftBtn;
        this.SlideRightBtn = slideRightBtn;
        this.StepArrow = stepArrow;
        this.CloseBtn = closeBtn;
        this.SelectedAppArrow = selectedAppArrow;
        this.FirstUnitBGColorForOneStep = firstUnitBGColorForOneStep;
        this.SecondUnitBGColorForOneStep = secondUnitBGColorForOneStep;
        this.RewardUnitBGColorForOneStep = rewardUnitBGColorForOneStep;
    }

    public String getCirclePlayBtn() {
        if (this.CirclePlayBtn == null) {
            this.CirclePlayBtn = CPEConstant.PLAY_BTN_CIRCLE;
        }
        return this.CirclePlayBtn;
    }

    public void setCirclePlayBtn(String circlePlayBtn) {
        this.CirclePlayBtn = circlePlayBtn;
    }

    public String getSquarePlayBtn() {
        if (this.SquarePlayBtn == null) {
            this.SquarePlayBtn = CPEConstant.PLAY_BTN_SQUARE;
        }
        return this.SquarePlayBtn;
    }

    public void setSquarePlayBtn(String squarePlayBtn) {
        this.SquarePlayBtn = squarePlayBtn;
    }

    public String getMissionCheckOff() {
        if (this.MissionCheckOff == null) {
            this.MissionCheckOff = CPEConstant.MISSION_CHECK_OFF;
        }
        return this.MissionCheckOff;
    }

    public void setMissionCheckOff(String missionCheckOff) {
        this.MissionCheckOff = missionCheckOff;
    }

    public String getMissionCheckOn() {
        if (this.MissionCheckOn == null) {
            this.MissionCheckOn = CPEConstant.MISSION_CHECK_ON;
        }
        return this.MissionCheckOn;
    }

    public void setMissionCheckOn(String missionCheckOn) {
        this.MissionCheckOn = missionCheckOn;
    }

    public String getPlayBtnAreaBG() {
        if (this.PlayBtnAreaBG == null) {
            this.PlayBtnAreaBG = CPEConstant.PLAY_BTN_AREA_BG;
        }
        return this.PlayBtnAreaBG;
    }

    public void setPlayBtnAreaBG(String playBtnAreaBG) {
        this.PlayBtnAreaBG = playBtnAreaBG;
    }

    public String getSlideLeftBtn() {
        if (this.SlideLeftBtn == null) {
            this.SlideLeftBtn = CPEConstant.SLIDE_LEFT_BTN;
        }
        return this.SlideLeftBtn;
    }

    public void setSlideLeftBtn(String slideLeftBtn) {
        this.SlideLeftBtn = slideLeftBtn;
    }

    public String getSlideRightBtn() {
        if (this.SlideRightBtn == null) {
            this.SlideRightBtn = CPEConstant.SLIDE_RIGHT_BTN;
        }
        return this.SlideRightBtn;
    }

    public void setSlideRightBtn(String slideRightBtn) {
        this.SlideRightBtn = slideRightBtn;
    }

    public String getStepArrow() {
        if (this.StepArrow == null) {
            this.StepArrow = CPEConstant.STEP_ARROW;
        }
        return this.StepArrow;
    }

    public void setStepArrow(String stepArrow) {
        this.StepArrow = stepArrow;
    }

    public String getCloseBtn() {
        if (this.CloseBtn == null) {
            this.CloseBtn = "http://static.adbrix.igaworks.com/adbrix_res/sdk_res/popup_close_bt.png";
        }
        return this.CloseBtn;
    }

    public void setCloseBtn(String closeBtn) {
        this.CloseBtn = closeBtn;
    }

    public String getSelectedAppArrow() {
        if (this.SelectedAppArrow == null) {
            this.SelectedAppArrow = CPEConstant.SELECTED_APP_ARROW;
        }
        return this.SelectedAppArrow;
    }

    public void setSelectedAppArrow(String selectedAppArrow) {
        this.SelectedAppArrow = selectedAppArrow;
    }

    public String getFirstUnitBGColorForOneStep() {
        if (this.FirstUnitBGColorForOneStep == null) {
            this.FirstUnitBGColorForOneStep = "#24e6e8";
        }
        return this.FirstUnitBGColorForOneStep;
    }

    public void setFirstUnitBGColorForOneStep(String firstUnitBGColorForOneStep) {
        this.FirstUnitBGColorForOneStep = firstUnitBGColorForOneStep;
    }

    public String getSecondUnitBGColorForOneStep() {
        if (this.SecondUnitBGColorForOneStep == null) {
            this.SecondUnitBGColorForOneStep = "#24e6e8";
        }
        return this.SecondUnitBGColorForOneStep;
    }

    public void setSecondUnitBGColorForOneStep(String secondUnitBGColorForOneStep) {
        this.SecondUnitBGColorForOneStep = secondUnitBGColorForOneStep;
    }

    public String getRewardUnitBGColorForOneStep() {
        if (this.RewardUnitBGColorForOneStep == null) {
            this.RewardUnitBGColorForOneStep = CPEConstant.REWARD_UNIT_BG_COLOR_FOR_ONE_STEP;
        }
        return this.RewardUnitBGColorForOneStep;
    }

    public void setRewardUnitBGColorForOneStep(String rewardUnitBGColorForOneStep) {
        this.RewardUnitBGColorForOneStep = rewardUnitBGColorForOneStep;
    }
}