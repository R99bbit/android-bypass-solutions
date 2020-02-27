package com.igaworks.adbrix.model;

public class Media {
    private Language Language;
    private String RewardIcon;
    private String RewardName;
    private Theme Theme;

    public Media() {
    }

    public Media(String rewardName, String rewardIcon, Theme theme, Language language) {
        this.RewardName = rewardName;
        this.RewardIcon = rewardIcon;
        this.Theme = theme;
        this.Language = language;
    }

    public String getRewardName() {
        return this.RewardName;
    }

    public void setRewardName(String rewardName) {
        this.RewardName = rewardName;
    }

    public String getRewardIcon() {
        return this.RewardIcon;
    }

    public void setRewardIcon(String rewardIcon) {
        this.RewardIcon = rewardIcon;
    }

    public Theme getTheme() {
        return this.Theme;
    }

    public void setTheme(Theme theme) {
        this.Theme = theme;
    }

    public Language getLanguage() {
        return this.Language;
    }

    public void setLanguage(Language language) {
        this.Language = language;
    }
}