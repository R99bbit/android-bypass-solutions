package com.igaworks.adbrix.model;

public class ViralCPIModel {
    private int CampaignKey;
    private String CheckRewardText;
    private String CloseBtnColorCode;
    private String CloseBtnTextColorCode;
    private String CompleteCopyText;
    private int ConversionKey;
    private boolean IsTrackingURLSetting = false;
    private String ItemName;
    private String ItemQuantity;
    private String ItemURL;
    private String NoMoreShowColorCode;
    private String NoMoreShowText;
    private long ParentConversionKey;
    private String RewardDetailText;
    private String RewardText;
    private String SharingMessage;
    private String SharingTitle;
    private boolean ShowOnlyOnce;
    private String TopbarColorCode;
    private String TopbarTitleTextColorCode;
    private String ViralConfirmBtnColorCode;
    private String ViralConfirmBtnText;
    private String ViralConfirmBtnTextColorCode;
    private String ViralInfoDialogBGColorCode;
    private String ViralInfoTitle;
    private String ViralMessage;
    private String referralKey;
    private String subconversionKey;

    public ViralCPIModel() {
    }

    public ViralCPIModel(String referralKey2, String subconversionKey2, int conversionKey, long parentConversionKey, int campaignKey, String viralMessage, String viralInfoTitle, String rewardText, String rewardDetailText, String checkRewardText, String viralConfirmBtnText, String sharingTitle, String sharingMessage, String noMoreShowText, String completeCopyText, String topbarColorCode, String topbarTitleTextColorCode, String viralInfoDialogBGColorCode, String viralConfirmBtnColorCode, String viralConfirmBtnTextColorCode, String closeBtnColorCode, String closeBtnTextColorCode, String noMoreShowColorCode, boolean showOnlyOnce) {
        this.referralKey = referralKey2;
        this.subconversionKey = subconversionKey2;
        this.ConversionKey = conversionKey;
        this.ParentConversionKey = parentConversionKey;
        this.CampaignKey = campaignKey;
        this.ViralMessage = viralMessage;
        this.ViralInfoTitle = viralInfoTitle;
        this.RewardText = rewardText;
        this.RewardDetailText = rewardDetailText;
        this.CheckRewardText = checkRewardText;
        this.ViralConfirmBtnText = viralConfirmBtnText;
        this.SharingTitle = sharingTitle;
        this.SharingMessage = sharingMessage;
        this.NoMoreShowText = noMoreShowText;
        this.CompleteCopyText = completeCopyText;
        this.TopbarColorCode = topbarColorCode;
        this.TopbarTitleTextColorCode = topbarTitleTextColorCode;
        this.ViralInfoDialogBGColorCode = viralInfoDialogBGColorCode;
        this.ViralConfirmBtnColorCode = viralConfirmBtnColorCode;
        this.ViralConfirmBtnTextColorCode = viralConfirmBtnTextColorCode;
        this.CloseBtnColorCode = closeBtnColorCode;
        this.CloseBtnTextColorCode = closeBtnTextColorCode;
        this.NoMoreShowColorCode = noMoreShowColorCode;
        this.ShowOnlyOnce = showOnlyOnce;
    }

    public boolean isIsTrackingURLSetting() {
        return this.IsTrackingURLSetting;
    }

    public void setIsTrackingURLSetting(boolean isTrackingURLSetting) {
        this.IsTrackingURLSetting = isTrackingURLSetting;
    }

    public String getItemURL() {
        return this.ItemURL;
    }

    public void setItemURL(String itemURL) {
        this.ItemURL = itemURL;
    }

    public String getItemName() {
        return this.ItemName;
    }

    public void setItemName(String itemName) {
        this.ItemName = itemName;
    }

    public String getItemQuantity() {
        return this.ItemQuantity;
    }

    public void setItemQuantity(String itemQuantity) {
        this.ItemQuantity = itemQuantity;
    }

    public String getReferralKey() {
        return this.referralKey;
    }

    public void setReferralKey(String referralKey2) {
        this.referralKey = referralKey2;
    }

    public String getSubconversionKey() {
        return this.subconversionKey;
    }

    public void setSubconversionKey(String subconversionKey2) {
        this.subconversionKey = subconversionKey2;
    }

    public int getConversionKey() {
        return this.ConversionKey;
    }

    public void setConversionKey(int conversionKey) {
        this.ConversionKey = conversionKey;
    }

    public long getParentConversionKey() {
        return this.ParentConversionKey;
    }

    public void setParentConversionKey(long parentConversionKey) {
        this.ParentConversionKey = parentConversionKey;
    }

    public int getCampaignKey() {
        return this.CampaignKey;
    }

    public void setCampaignKey(int campaignKey) {
        this.CampaignKey = campaignKey;
    }

    public String getViralMessage() {
        return this.ViralMessage;
    }

    public void setViralMessage(String viralMessage) {
        this.ViralMessage = viralMessage;
    }

    public String getViralInfoTitle() {
        return this.ViralInfoTitle;
    }

    public void setViralInfoTitle(String viralInfoTitle) {
        this.ViralInfoTitle = viralInfoTitle;
    }

    public String getRewardText() {
        return this.RewardText;
    }

    public void setRewardText(String rewardText) {
        this.RewardText = rewardText;
    }

    public String getRewardDetailText() {
        return this.RewardDetailText;
    }

    public void setRewardDetailText(String rewardDetailText) {
        this.RewardDetailText = rewardDetailText;
    }

    public String getCheckRewardText() {
        return this.CheckRewardText;
    }

    public void setCheckRewardText(String checkRewardText) {
        this.CheckRewardText = checkRewardText;
    }

    public String getViralConfirmBtnText() {
        return this.ViralConfirmBtnText;
    }

    public void setViralConfirmBtnText(String viralConfirmBtnText) {
        this.ViralConfirmBtnText = viralConfirmBtnText;
    }

    public String getSharingTitle() {
        return this.SharingTitle;
    }

    public void setSharingTitle(String sharingTitle) {
        this.SharingTitle = sharingTitle;
    }

    public String getSharingMessage() {
        return this.SharingMessage;
    }

    public void setSharingMessage(String sharingMessage) {
        this.SharingMessage = sharingMessage;
    }

    public String getNoMoreShowText() {
        return this.NoMoreShowText;
    }

    public void setNoMoreShowText(String noMoreShowText) {
        this.NoMoreShowText = noMoreShowText;
    }

    public String getCompleteCopyText() {
        return this.CompleteCopyText;
    }

    public void setCompleteCopyText(String completeCopyText) {
        this.CompleteCopyText = completeCopyText;
    }

    public String getTopbarColorCode() {
        return this.TopbarColorCode;
    }

    public void setTopbarColorCode(String topbarColorCode) {
        this.TopbarColorCode = topbarColorCode;
    }

    public String getTopbarTitleTextColorCode() {
        return this.TopbarTitleTextColorCode;
    }

    public void setTopbarTitleTextColorCode(String topbarTitleTextColorCode) {
        this.TopbarTitleTextColorCode = topbarTitleTextColorCode;
    }

    public String getViralInfoDialogBGColorCode() {
        return this.ViralInfoDialogBGColorCode;
    }

    public void setViralInfoDialogBGColorCode(String viralInfoDialogBGColorCode) {
        this.ViralInfoDialogBGColorCode = viralInfoDialogBGColorCode;
    }

    public String getViralConfirmBtnColorCode() {
        return this.ViralConfirmBtnColorCode;
    }

    public void setViralConfirmBtnColorCode(String viralConfirmBtnColorCode) {
        this.ViralConfirmBtnColorCode = viralConfirmBtnColorCode;
    }

    public String getViralConfirmBtnTextColorCode() {
        return this.ViralConfirmBtnTextColorCode;
    }

    public void setViralConfirmBtnTextColorCode(String viralConfirmBtnTextColorCode) {
        this.ViralConfirmBtnTextColorCode = viralConfirmBtnTextColorCode;
    }

    public String getCloseBtnColorCode() {
        return this.CloseBtnColorCode;
    }

    public void setCloseBtnColorCode(String closeBtnColorCode) {
        this.CloseBtnColorCode = closeBtnColorCode;
    }

    public String getCloseBtnTextColorCode() {
        return this.CloseBtnTextColorCode;
    }

    public void setCloseBtnTextColorCode(String closeBtnTextColorCode) {
        this.CloseBtnTextColorCode = closeBtnTextColorCode;
    }

    public String getNoMoreShowColorCode() {
        return this.NoMoreShowColorCode;
    }

    public void setNoMoreShowColorCode(String noMoreShowColorCode) {
        this.NoMoreShowColorCode = noMoreShowColorCode;
    }

    public boolean isShowOnlyOnce() {
        return this.ShowOnlyOnce;
    }

    public void setShowOnlyOnce(boolean showOnlyOnce) {
        this.ShowOnlyOnce = showOnlyOnce;
    }
}