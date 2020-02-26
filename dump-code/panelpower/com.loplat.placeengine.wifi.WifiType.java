package com.loplat.placeengine.wifi;

import a.a.a.a.a;
import com.google.gson.annotations.SerializedName;
import java.io.Serializable;

public class WifiType implements Serializable {
    @SerializedName("bssid")
    public String BSSID;
    @SerializedName("ssid")
    public String SSID;
    @SerializedName("frequency")
    public int frequency;
    @SerializedName("rss")
    public int level;

    public WifiType(String str, String str2, int i, int i2) {
        this.BSSID = str;
        this.SSID = str2;
        this.level = i;
        this.frequency = i2;
    }

    public boolean equals(Object obj) {
        if (obj instanceof WifiType) {
            WifiType wifiType = (WifiType) obj;
            if (this.BSSID.equals(wifiType.BSSID) && this.frequency / 1000 == wifiType.frequency / 1000) {
                return true;
            }
        }
        return false;
    }

    public int hashCode() {
        StringBuilder a2 = a.a("");
        a2.append(this.BSSID);
        a2.append(this.frequency / 1000);
        return a2.toString().hashCode();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.BSSID);
        sb.append(",");
        sb.append(this.frequency);
        sb.append(",");
        sb.append(this.level);
        sb.append(",");
        sb.append(this.SSID);
        sb.append("\n");
        return sb.toString();
    }

    public WifiType(String str, int i) {
        this.BSSID = str;
        this.SSID = null;
        this.level = i;
        this.frequency = 0;
    }

    public WifiType() {
    }
}