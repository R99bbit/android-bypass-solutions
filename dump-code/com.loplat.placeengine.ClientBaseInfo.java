package com.loplat.placeengine;

import a.b.a.b.l;
import a.b.a.g.a;
import a.b.a.h.d;
import android.content.Context;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;

public class ClientBaseInfo implements Parcelable {
    public static final Creator<ClientBaseInfo> CREATOR = new a();
    public String anid;
    public String application;
    public String client_id;
    public String client_secret;
    public int configID;
    public String echo_code;
    public boolean enableAdNetwork;
    public boolean isBackgroundRestricted;
    public int sdkMode;
    public String sdkversion;
    public int standByBucket;

    public ClientBaseInfo(Context context) {
        this.client_id = l.k;
        this.client_secret = l.l;
        this.application = a.a(context);
        this.sdkversion = "2.0.8.2";
        this.echo_code = PlaceEngineBase.getEchoCode(context);
        this.anid = PlaceEngineBase.getANID(context);
        this.enableAdNetwork = PlaceEngineBase.isEnabledAdNetwork(context);
        this.standByBucket = d.a(context).f46a;
        this.configID = PlaceEngineBase.getConfigId(context);
        this.sdkMode = a.h(context);
    }

    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        if (obj instanceof ClientBaseInfo) {
            ClientBaseInfo clientBaseInfo = (ClientBaseInfo) obj;
            if (getClientId().equals(clientBaseInfo.getClientId()) && getClientSecret().equals(clientBaseInfo.getClientSecret()) && getAppPackage().equals(clientBaseInfo.getAppPackage())) {
                return true;
            }
        }
        return false;
    }

    public String getAnid() {
        return this.anid;
    }

    public String getAppPackage() {
        return this.application;
    }

    public String getClientId() {
        return this.client_id;
    }

    public String getClientSecret() {
        return this.client_secret;
    }

    public String getEchoCode() {
        return this.echo_code;
    }

    public int getSdkMode() {
        return this.sdkMode;
    }

    public String getSdkVer() {
        return this.sdkversion;
    }

    public int getStandByBucket() {
        return this.standByBucket;
    }

    public boolean isBackgroundRestricted() {
        return this.isBackgroundRestricted;
    }

    public boolean isClientActiveOrWorkingSet() {
        int i = this.standByBucket;
        return i == 10 || i == 20;
    }

    public boolean isEnableAdNetwork() {
        return this.enableAdNetwork;
    }

    public void setBackgroundRestricted(boolean z) {
        this.isBackgroundRestricted = z;
    }

    public void setEnableAdNetwork(boolean z) {
        this.enableAdNetwork = z;
    }

    public void setSdkMode(int i) {
        this.sdkMode = i;
    }

    public void setStandByBucket(int i) {
        this.standByBucket = i;
    }

    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeString(this.client_id);
        parcel.writeString(this.client_secret);
        parcel.writeString(this.application);
        parcel.writeString(this.sdkversion);
        parcel.writeString(this.echo_code);
        parcel.writeString(this.anid);
        parcel.writeByte(this.enableAdNetwork ? (byte) 1 : 0);
        parcel.writeInt(this.standByBucket);
        parcel.writeInt(this.configID);
        parcel.writeByte(this.isBackgroundRestricted ? (byte) 1 : 0);
        parcel.writeInt(this.sdkMode);
    }

    public ClientBaseInfo(Parcel parcel) {
        this.client_id = parcel.readString();
        this.client_secret = parcel.readString();
        this.application = parcel.readString();
        this.sdkversion = parcel.readString();
        this.echo_code = parcel.readString();
        this.anid = parcel.readString();
        boolean z = true;
        this.enableAdNetwork = parcel.readByte() != 0;
        this.standByBucket = parcel.readInt();
        this.configID = parcel.readInt();
        this.isBackgroundRestricted = parcel.readByte() == 0 ? false : z;
        this.sdkMode = parcel.readInt();
    }
}