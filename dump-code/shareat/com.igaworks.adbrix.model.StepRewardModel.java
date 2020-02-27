package com.igaworks.adbrix.model;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;

public class StepRewardModel implements Parcelable {
    public static final Creator CREATOR = new Creator() {
        public StepRewardModel createFromParcel(Parcel source) {
            return new StepRewardModel(source);
        }

        public StepRewardModel[] newArray(int size) {
            return new StepRewardModel[size];
        }
    };
    private int ConversionKey;
    private String Name;
    private int Reward;
    private boolean isComplete = false;

    public StepRewardModel() {
    }

    public StepRewardModel(int conversionKey, String name, int reward) {
        this.ConversionKey = conversionKey;
        this.Name = name;
        this.Reward = reward;
    }

    public int getConversionKey() {
        return this.ConversionKey;
    }

    public void setConversionKey(int conversionKey) {
        this.ConversionKey = conversionKey;
    }

    public String getName() {
        return this.Name;
    }

    public void setName(String name) {
        this.Name = name;
    }

    public int getReward() {
        return this.Reward;
    }

    public void setReward(int reward) {
        this.Reward = reward;
    }

    public boolean isComplete() {
        return this.isComplete;
    }

    public void setComplete(boolean isComplete2) {
        this.isComplete = isComplete2;
    }

    public StepRewardModel(Parcel src) {
        this.ConversionKey = src.readInt();
        this.Name = src.readString();
        this.Reward = src.readInt();
        this.isComplete = Boolean.parseBoolean(src.readString());
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(this.ConversionKey);
        dest.writeString(this.Name);
        dest.writeInt(this.Reward);
        dest.writeString(new StringBuilder(String.valueOf(this.isComplete)).toString());
    }
}