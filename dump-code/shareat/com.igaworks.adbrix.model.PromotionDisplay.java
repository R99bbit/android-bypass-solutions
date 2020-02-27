package com.igaworks.adbrix.model;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import java.util.ArrayList;
import java.util.List;

public class PromotionDisplay implements Parcelable {
    public static final Creator CREATOR = new Creator() {
        public PromotionDisplay createFromParcel(Parcel source) {
            return new PromotionDisplay(source);
        }

        public PromotionDisplay[] newArray(int size) {
            return new PromotionDisplay[size];
        }
    };
    private String ClickUrl;
    private IconModel Icon;
    private boolean IsMarketUrl;
    private SlideModel Slides;
    private List<StepRewardModel> StepReward;
    private String Title;
    private int Type;

    public PromotionDisplay() {
    }

    public PromotionDisplay(String title, IconModel icon, SlideModel slide, int type, String clickUrl, boolean IsMarketUrl2, List<StepRewardModel> stepReward) {
        this.Title = title;
        this.Icon = icon;
        this.Slides = slide;
        this.Type = type;
        this.ClickUrl = clickUrl;
        this.IsMarketUrl = IsMarketUrl2;
        this.StepReward = stepReward;
    }

    public String getTitle() {
        return this.Title;
    }

    public void setTitle(String title) {
        this.Title = title;
    }

    public IconModel getIcon() {
        return this.Icon;
    }

    public void setIcon(IconModel icon) {
        this.Icon = icon;
    }

    public SlideModel getSlide() {
        return this.Slides;
    }

    public void setSlide(SlideModel slide) {
        this.Slides = slide;
    }

    public int getType() {
        return this.Type;
    }

    public void setType(int type) {
        this.Type = type;
    }

    public String getClickUrl() {
        return this.ClickUrl;
    }

    public void setClickUrl(String clickUrl) {
        this.ClickUrl = clickUrl;
    }

    public List<StepRewardModel> getStepReward() {
        return this.StepReward;
    }

    public void setStepReward(List<StepRewardModel> stepReward) {
        this.StepReward = stepReward;
    }

    public boolean isIsMarketUrl() {
        return this.IsMarketUrl;
    }

    public void setIsMarketUrl(boolean isMarketUrl) {
        this.IsMarketUrl = isMarketUrl;
    }

    public PromotionDisplay(Parcel src) {
        this.Title = src.readString();
        this.Icon = (IconModel) src.readParcelable(IconModel.class.getClassLoader());
        this.Slides = (SlideModel) src.readParcelable(SlideModel.class.getClassLoader());
        this.Type = src.readInt();
        this.ClickUrl = src.readString();
        this.IsMarketUrl = Boolean.parseBoolean(src.readString());
        this.StepReward = new ArrayList();
        src.readTypedList(this.StepReward, StepRewardModel.CREATOR);
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(this.Title);
        dest.writeParcelable(this.Icon, flags);
        dest.writeParcelable(this.Slides, flags);
        dest.writeInt(this.Type);
        dest.writeString(this.ClickUrl);
        dest.writeString(new StringBuilder(String.valueOf(this.IsMarketUrl)).toString());
        dest.writeTypedList(this.StepReward);
    }
}