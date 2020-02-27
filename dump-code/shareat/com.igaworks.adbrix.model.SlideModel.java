package com.igaworks.adbrix.model;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import java.util.List;

public class SlideModel implements Parcelable {
    public static final Creator CREATOR = new Creator() {
        public SlideModel createFromParcel(Parcel source) {
            return new SlideModel(source);
        }

        public SlideModel[] newArray(int size) {
            return new SlideModel[size];
        }
    };
    private List<String> Resource;
    private int ResourceKey;

    public SlideModel() {
    }

    public SlideModel(int resourceKey, List<String> resource) {
        this.ResourceKey = resourceKey;
        this.Resource = resource;
    }

    public int getResourceKey() {
        return this.ResourceKey;
    }

    public void setResourceKey(int resourceKey) {
        this.ResourceKey = resourceKey;
    }

    public List<String> getResource() {
        return this.Resource;
    }

    public void setResource(List<String> resource) {
        this.Resource = resource;
    }

    public SlideModel(Parcel parcel) {
        this.ResourceKey = parcel.readInt();
        parcel.readStringList(this.Resource);
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(this.ResourceKey);
        dest.writeStringList(this.Resource);
    }
}