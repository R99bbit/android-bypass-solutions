package com.igaworks.adbrix.model;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;

public class IconModel implements Parcelable {
    public static final Creator CREATOR = new Creator() {
        public IconModel createFromParcel(Parcel source) {
            return new IconModel(source);
        }

        public IconModel[] newArray(int size) {
            return new IconModel[size];
        }
    };
    private String Resource;
    private int ResourceKey;

    public IconModel() {
    }

    public IconModel(int resourceKey, String resource) {
        this.ResourceKey = resourceKey;
        this.Resource = resource;
    }

    public int getResourceKey() {
        return this.ResourceKey;
    }

    public void setResourceKey(int resourceKey) {
        this.ResourceKey = resourceKey;
    }

    public String getResource() {
        return this.Resource;
    }

    public void setResource(String resource) {
        this.Resource = resource;
    }

    public IconModel(Parcel src) {
        this.Resource = src.readString();
        this.ResourceKey = src.readInt();
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(this.Resource);
        dest.writeInt(this.ResourceKey);
    }
}