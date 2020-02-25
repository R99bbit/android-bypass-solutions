package com.loplat.placeengine.cloud;

import a.a.a.a.a;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import com.google.gson.annotations.SerializedName;
import com.loplat.placeengine.PlengiResponse.Area;
import com.loplat.placeengine.PlengiResponse.Complex;
import com.loplat.placeengine.PlengiResponse.District;
import com.loplat.placeengine.PlengiResponse.Location;
import com.loplat.placeengine.PlengiResponse.Place;
import com.loplat.placeengine.wifi.WifiType;
import java.io.Serializable;
import java.util.ArrayList;

public class ResponseMessage implements Serializable {
    public static final String STATUS_FAIL = "fail";
    public static final String STATUS_SUCCESS = "success";

    public static class ActivityRecognition implements Parcelable {
        public static final Creator<ActivityRecognition> CREATOR = new Creator<ActivityRecognition>() {
            public ActivityRecognition createFromParcel(Parcel parcel) {
                return new ActivityRecognition(parcel);
            }

            public ActivityRecognition[] newArray(int i) {
                return new ActivityRecognition[i];
            }
        };
        @SerializedName("check_distance")
        public int checkDistance;
        @SerializedName("check_interval")
        public int checkInterval;

        public ActivityRecognition(Parcel parcel) {
            this.checkDistance = parcel.readInt();
            this.checkInterval = parcel.readInt();
        }

        public int describeContents() {
            return 0;
        }

        public int getCheckDistance() {
            return this.checkDistance;
        }

        public int getCheckInterval() {
            return this.checkInterval;
        }

        public boolean isValidSetting() {
            return this.checkDistance > 0 && this.checkInterval > 0;
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeInt(this.checkDistance);
            parcel.writeInt(this.checkInterval);
        }
    }

    public static class Advertisement implements Parcelable {
        public static final Creator<Advertisement> CREATOR = new Creator<Advertisement>() {
            public Advertisement createFromParcel(Parcel parcel) {
                return new Advertisement(parcel);
            }

            public Advertisement[] newArray(int i) {
                return new Advertisement[i];
            }
        };
        @SerializedName("ad")
        public boolean ad;
        @SerializedName("alarm")
        public String alarm;
        @SerializedName("body")
        public String body;
        @SerializedName("campaign_id")
        public int campaign_id;
        @SerializedName("client_code")
        public String client_code;
        @SerializedName("delay")
        public long delay;
        @SerializedName("delay_type")
        public String delay_type;
        @SerializedName("img")
        public String image_url;
        @SerializedName("intent")
        public String intent;
        @SerializedName("msg_id")
        public int msg_id;
        @SerializedName("target_pkg")
        public String target_pkg;
        public long time;
        @SerializedName("title")
        public String title;

        public Advertisement(Parcel parcel) {
            this.ad = parcel.readByte() != 0;
            this.alarm = parcel.readString();
            this.title = parcel.readString();
            this.body = parcel.readString();
            this.intent = parcel.readString();
            this.target_pkg = parcel.readString();
            this.msg_id = parcel.readInt();
            this.delay_type = parcel.readString();
            this.delay = parcel.readLong();
            this.image_url = parcel.readString();
            this.campaign_id = parcel.readInt();
            this.client_code = parcel.readString();
            this.time = parcel.readLong();
        }

        public void SetClientCode(String str) {
            this.client_code = str;
        }

        public int describeContents() {
            return 0;
        }

        public String getAlarm() {
            return this.alarm;
        }

        public String getBody() {
            return this.body;
        }

        public int getCampaign_id() {
            return this.campaign_id;
        }

        public String getClientCode() {
            return this.client_code;
        }

        public long getDelay() {
            return this.delay;
        }

        public String getDelay_type() {
            return this.delay_type;
        }

        public String getImage_url() {
            return this.image_url;
        }

        public String getIntent() {
            return this.intent;
        }

        public int getMsg_id() {
            return this.msg_id;
        }

        public String getTarget_pkg() {
            return this.target_pkg;
        }

        public long getTime() {
            return this.time;
        }

        public String getTitle() {
            return this.title;
        }

        public boolean hasAd() {
            return this.ad;
        }

        public void setAlarm(String str) {
            this.alarm = str;
        }

        public void setBody(String str) {
            this.body = str;
        }

        public void setCampaign_id(int i) {
            this.campaign_id = i;
        }

        public void setDelay(long j) {
            this.delay = j;
        }

        public void setDelay_type(String str) {
            this.delay_type = str;
        }

        public void setHasAd(boolean z) {
            this.ad = z;
        }

        public void setImage_url(String str) {
            this.image_url = str;
        }

        public void setIntent(String str) {
            this.intent = str;
        }

        public void setMsg_id(int i) {
            this.msg_id = i;
        }

        public void setTarget_pkg(String str) {
            this.target_pkg = str;
        }

        public void setTime(long j) {
            this.time = j;
        }

        public void setTitle(String str) {
            this.title = str;
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeByte(this.ad ? (byte) 1 : 0);
            parcel.writeString(this.alarm);
            parcel.writeString(this.title);
            parcel.writeString(this.body);
            parcel.writeString(this.intent);
            parcel.writeString(this.target_pkg);
            parcel.writeInt(this.msg_id);
            parcel.writeString(this.delay_type);
            parcel.writeLong(this.delay);
            parcel.writeString(this.image_url);
            parcel.writeInt(this.campaign_id);
            parcel.writeString(this.client_code);
            parcel.writeLong(this.time);
        }
    }

    public static abstract class BaseResMessage {
        @SerializedName("anid")
        public String anid;
        @SerializedName("reason")
        public String reason;
        @SerializedName("status")
        public String status;
        @SerializedName("type")
        public String type;

        public String getAnid() {
            return this.anid;
        }

        public String getReason() {
            return this.reason;
        }

        public String getStatus() {
            return this.status;
        }

        public String getType() {
            return this.type;
        }

        public void setAnid(String str) {
            this.anid = str;
        }

        public void setReason(String str) {
            this.reason = str;
        }

        public void setStatus(String str) {
            this.status = str;
        }

        public void setType(String str) {
            this.type = str;
        }
    }

    public static class CellLoc implements Parcelable {
        public static final Creator<CellLoc> CREATOR = new Creator<CellLoc>() {
            public CellLoc createFromParcel(Parcel parcel) {
                return new CellLoc(parcel);
            }

            public CellLoc[] newArray(int i) {
                return new CellLoc[i];
            }
        };
        @SerializedName("ad_by_cell")
        public boolean adByCell;
        @SerializedName("cell_move")
        public int cellMove;
        @SerializedName("cell_stay")
        public int cellStay;
        @SerializedName("lbs_id")
        public String lbsId;
        @SerializedName("lbs_key")
        public String lbsKey;
        @SerializedName("lbs_url")
        public String lbsUrl;

        public CellLoc(Parcel parcel) {
            this.cellMove = parcel.readInt();
            this.cellStay = parcel.readInt();
            this.adByCell = parcel.readByte() != 0;
            this.lbsUrl = parcel.readString();
            this.lbsId = parcel.readString();
            this.lbsKey = parcel.readString();
        }

        public int describeContents() {
            return 0;
        }

        public String getLbsId() {
            return this.lbsId;
        }

        public String getLbsKey() {
            return this.lbsKey;
        }

        public String getLbsUrl() {
            return this.lbsUrl;
        }

        public int getPeriodCellMove() {
            return this.cellMove;
        }

        public int getPeriodCellStay() {
            return this.cellStay;
        }

        public boolean isAdByCell() {
            return this.adByCell;
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeInt(this.cellMove);
            parcel.writeInt(this.cellStay);
            parcel.writeByte(this.adByCell ? (byte) 1 : 0);
            parcel.writeString(this.lbsUrl);
            parcel.writeString(this.lbsId);
            parcel.writeString(this.lbsKey);
        }
    }

    public class ConfigSdkEventRes extends BaseResMessage {
        @SerializedName("config")
        public SdkConfig config;

        public ConfigSdkEventRes() {
        }

        public SdkConfig getConfig() {
            return this.config;
        }

        public void setConfig(SdkConfig sdkConfig) {
            this.config = sdkConfig;
        }
    }

    public static class Fence implements Parcelable {
        public static final Creator<Fence> CREATOR = new Creator<Fence>() {
            public Fence createFromParcel(Parcel parcel) {
                return new Fence(parcel);
            }

            public Fence[] newArray(int i) {
                return new Fence[i];
            }
        };
        @SerializedName("client_code")
        public String clientCode;
        @SerializedName("dist")
        public float dist;
        @SerializedName("gfid")
        public long gfId;
        @SerializedName("name")
        public String name;

        public Fence(Parcel parcel) {
            this.gfId = parcel.readLong();
            this.dist = parcel.readFloat();
            this.name = parcel.readString();
            this.clientCode = parcel.readString();
        }

        public int describeContents() {
            return 0;
        }

        public String getClientCode() {
            return this.clientCode;
        }

        public float getDist() {
            return this.dist;
        }

        public long getGfId() {
            return this.gfId;
        }

        public String getName() {
            return this.name;
        }

        public void setClientCode(String str) {
            this.clientCode = str;
        }

        public void setDist(float f) {
            this.dist = f;
        }

        public void setGfId(long j) {
            this.gfId = j;
        }

        public void setName(String str) {
            this.name = str;
        }

        public String toString() {
            return String.format("[gfid: %d, dist: %f, name: %s, client_code: %s]", new Object[]{Long.valueOf(this.gfId), Float.valueOf(this.dist), this.name, this.clientCode});
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeLong(this.gfId);
            parcel.writeFloat(this.dist);
            parcel.writeString(this.name);
            parcel.writeString(this.clientCode);
        }
    }

    public class Friend {
        @SerializedName("deviceid")
        public String deviceid;
        @SerializedName("name")
        public String name;

        public Friend() {
        }

        public String getDeviceid() {
            return this.deviceid;
        }

        public String getName() {
            return this.name;
        }

        public void setDeviceid(String str) {
            this.deviceid = str;
        }

        public void setName(String str) {
            this.name = str;
        }
    }

    public static class GeoFence implements Parcelable {
        public static final Creator<GeoFence> CREATOR = new Creator<GeoFence>() {
            public GeoFence createFromParcel(Parcel parcel) {
                return new GeoFence(parcel);
            }

            public GeoFence[] newArray(int i) {
                return new GeoFence[i];
            }
        };
        @SerializedName("fences")
        public ArrayList<Fence> fences;
        @SerializedName("lat")
        public double lat;
        @SerializedName("lng")
        public double lng;

        public GeoFence(Parcel parcel) {
            this.lat = parcel.readDouble();
            this.lng = parcel.readDouble();
            this.fences = parcel.createTypedArrayList(Fence.CREATOR);
        }

        public int describeContents() {
            return 0;
        }

        public ArrayList<Fence> getFences() {
            return this.fences;
        }

        public double getLat() {
            return this.lat;
        }

        public double getLng() {
            return this.lng;
        }

        public void setFences(ArrayList<Fence> arrayList) {
            this.fences = arrayList;
        }

        public void setLat(double d) {
            this.lat = d;
        }

        public void setLng(double d) {
            this.lng = d;
        }

        public String toString() {
            StringBuilder a2 = a.a("(location: ");
            a2.append(this.lat);
            a2.append(", ");
            a2.append(this.lng);
            a2.append("), ");
            a2.append(this.fences.toString());
            return a2.toString();
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeDouble(this.lat);
            parcel.writeDouble(this.lng);
            parcel.writeTypedList(this.fences);
        }
    }

    public class LeavePlaceRes extends BaseResMessage {
        public LeavePlaceRes() {
        }
    }

    public static class Nearbys implements Parcelable {
        public static final Creator<Nearbys> CREATOR = new Creator<Nearbys>() {
            public Nearbys createFromParcel(Parcel parcel) {
                return new Nearbys(parcel);
            }

            public Nearbys[] newArray(int i) {
                return new Nearbys[i];
            }
        };
        @SerializedName("accuracy")
        public float accuracy;
        @SerializedName("floor")
        public int floor;
        @SerializedName("lat")
        public double lat;
        @SerializedName("lng")
        public double lng;
        @SerializedName("loplat_id")
        public long loplatid;
        @SerializedName("placename")
        public String placename;
        @SerializedName("tags")
        public String tags;

        public Nearbys(Parcel parcel) {
            this.loplatid = parcel.readLong();
            this.placename = parcel.readString();
            this.tags = parcel.readString();
            this.floor = parcel.readInt();
            this.lat = parcel.readDouble();
            this.lng = parcel.readDouble();
            this.accuracy = parcel.readFloat();
        }

        public int describeContents() {
            return 0;
        }

        public float getAccuracy() {
            return this.accuracy;
        }

        public int getFloor() {
            return this.floor;
        }

        public double getLat() {
            return this.lat;
        }

        public double getLng() {
            return this.lng;
        }

        public long getLoplatid() {
            return this.loplatid;
        }

        public String getPlacename() {
            return this.placename;
        }

        public String getTags() {
            return this.tags;
        }

        public void setAccuracy(float f) {
            this.accuracy = f;
        }

        public void setFloor(int i) {
            this.floor = i;
        }

        public void setLat(double d) {
            this.lat = d;
        }

        public void setLng(double d) {
            this.lng = d;
        }

        public void setLoplatid(long j) {
            this.loplatid = j;
        }

        public void setPlacename(String str) {
            this.placename = str;
        }

        public void setTags(String str) {
            this.tags = str;
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeLong(this.loplatid);
            parcel.writeString(this.placename);
            parcel.writeString(this.tags);
            parcel.writeInt(this.floor);
            parcel.writeDouble(this.lat);
            parcel.writeDouble(this.lng);
            parcel.writeFloat(this.accuracy);
        }
    }

    public class RegisterUserRes extends ConfigSdkEventRes {
        public RegisterUserRes() {
            super();
        }
    }

    public class ReportPlaceEngState extends BaseResMessage {
        @SerializedName("config")
        public SdkConfig config;

        public ReportPlaceEngState() {
        }

        public SdkConfig getConfig() {
            return this.config;
        }

        public void setConfig(SdkConfig sdkConfig) {
            this.config = sdkConfig;
        }
    }

    public static class SdkConfig implements Parcelable {
        public static final Creator<SdkConfig> CREATOR = new Creator<SdkConfig>() {
            public SdkConfig createFromParcel(Parcel parcel) {
                return new SdkConfig(parcel);
            }

            public SdkConfig[] newArray(int i) {
                return new SdkConfig[i];
            }
        };
        @SerializedName("activity_loc")
        public ActivityRecognition activityRecognition;
        @SerializedName("ad_url")
        public String adUrl;
        @SerializedName("avoid_app_standby")
        public boolean avoid_app_standby;
        @SerializedName("avoid_doze")
        public boolean avoid_doze;
        @SerializedName("cell_loc")
        public CellLoc cellLoc;
        @SerializedName("config_id")
        public int configID;
        @SerializedName("fgs_noti_patched")
        public ArrayList<String> fgsNotiPatched;
        @SerializedName("force_stop")
        public boolean forceStop;
        @SerializedName("manual_api")
        public boolean manualApi;
        @SerializedName("multi_sdk")
        public multiSdk multiSdk;
        @SerializedName("period_move")
        public int periodMove;
        @SerializedName("period_stay")
        public int periodStay;
        @SerializedName("place_url")
        public String placeUrl;
        @SerializedName("sdk_mode")
        public int sdkMode;
        @SerializedName("unlock_screen_scan")
        public boolean unlock_screen_scan;
        @SerializedName("update_check_interval")
        public int updateCheckInterval;
        @SerializedName("use_adid")
        public boolean usedAdid;

        public SdkConfig(Parcel parcel) {
            this.configID = parcel.readInt();
            this.sdkMode = parcel.readInt();
            this.periodMove = parcel.readInt();
            this.periodStay = parcel.readInt();
            boolean z = true;
            this.unlock_screen_scan = parcel.readByte() != 0;
            this.avoid_doze = parcel.readByte() != 0;
            this.avoid_app_standby = parcel.readByte() != 0;
            this.multiSdk = (multiSdk) parcel.readParcelable(multiSdk.class.getClassLoader());
            this.cellLoc = (CellLoc) parcel.readParcelable(CellLoc.class.getClassLoader());
            this.usedAdid = parcel.readByte() != 0;
            this.forceStop = parcel.readByte() != 0;
            this.manualApi = parcel.readByte() == 0 ? false : z;
            this.updateCheckInterval = parcel.readInt();
            this.activityRecognition = (ActivityRecognition) parcel.readParcelable(ActivityRecognition.class.getClassLoader());
            this.adUrl = parcel.readString();
            this.placeUrl = parcel.readString();
            this.fgsNotiPatched = parcel.createStringArrayList();
        }

        public int describeContents() {
            return 0;
        }

        public boolean equals(Object obj) {
            return obj != null && (obj instanceof SdkConfig) && this.configID == ((SdkConfig) obj).getConfigID();
        }

        public ActivityRecognition getActivityRecognitionSetting() {
            return this.activityRecognition;
        }

        public String getAdUrl() {
            return this.adUrl;
        }

        public CellLoc getCellLoc() {
            return this.cellLoc;
        }

        public int getConfigID() {
            return this.configID;
        }

        public ArrayList<String> getFgsNotiPatched() {
            return this.fgsNotiPatched;
        }

        public int getPeriodMove() {
            return this.periodMove;
        }

        public int getPeriodStay() {
            return this.periodStay;
        }

        public String getPlaceUrl() {
            return this.placeUrl;
        }

        public String getSdkCh() {
            multiSdk multisdk = this.multiSdk;
            if (multisdk != null) {
                return multisdk.cmCh;
            }
            return null;
        }

        public String getSdkEncode() {
            multiSdk multisdk = this.multiSdk;
            if (multisdk != null) {
                return multisdk.code;
            }
            return null;
        }

        public int getSdkMode() {
            return this.sdkMode > 0 ? 1 : 0;
        }

        public int getUpdateCheckInterval() {
            return this.updateCheckInterval;
        }

        public boolean isAvoidAppStandby() {
            return this.avoid_app_standby;
        }

        public boolean isAvoidDoze() {
            return this.avoid_doze;
        }

        public boolean isCellLocation() {
            return this.cellLoc != null;
        }

        public boolean isForceStop() {
            return this.forceStop;
        }

        public boolean isManualApi() {
            return this.manualApi;
        }

        public boolean isMultiSdkTransaction() {
            return this.multiSdk != null;
        }

        public boolean isUnlockScreenScan() {
            return this.unlock_screen_scan;
        }

        public boolean isUseAdid() {
            return this.usedAdid;
        }

        public void setFgsNotiPatched(ArrayList<String> arrayList) {
            this.fgsNotiPatched = arrayList;
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeInt(this.configID);
            parcel.writeInt(this.sdkMode);
            parcel.writeInt(this.periodMove);
            parcel.writeInt(this.periodStay);
            parcel.writeByte(this.unlock_screen_scan ? (byte) 1 : 0);
            parcel.writeByte(this.avoid_doze ? (byte) 1 : 0);
            parcel.writeByte(this.avoid_app_standby ? (byte) 1 : 0);
            parcel.writeParcelable(this.multiSdk, i);
            parcel.writeParcelable(this.cellLoc, i);
            parcel.writeByte(this.usedAdid ? (byte) 1 : 0);
            parcel.writeByte(this.forceStop ? (byte) 1 : 0);
            parcel.writeByte(this.manualApi ? (byte) 1 : 0);
            parcel.writeInt(this.updateCheckInterval);
            parcel.writeParcelable(this.activityRecognition, i);
            parcel.writeString(this.adUrl);
            parcel.writeString(this.placeUrl);
            parcel.writeStringList(this.fgsNotiPatched);
        }
    }

    public static class SearchPlaceRes implements Parcelable {
        public static final Creator<SearchPlaceRes> CREATOR = new Creator<SearchPlaceRes>() {
            public SearchPlaceRes createFromParcel(Parcel parcel) {
                return new SearchPlaceRes(parcel);
            }

            public SearchPlaceRes[] newArray(int i) {
                return new SearchPlaceRes[i];
            }
        };
        @SerializedName("ad")
        public Advertisement ad;
        @SerializedName("anid")
        public String anid;
        @SerializedName("area")
        public Area area;
        @SerializedName("complex")
        public Complex complex;
        @SerializedName("config")
        public SdkConfig config;
        @SerializedName("district")
        public District district;
        @SerializedName("geofence")
        public GeoFence geoFence;
        @SerializedName("location")
        public Location location;
        @SerializedName("nearbys")
        public ArrayList<Nearbys> nearbys;
        @SerializedName("place")
        public Place place;
        @SerializedName("reason")
        public String reason;
        @SerializedName("req_id")
        public String req_id;
        @SerializedName("stations")
        public ArrayList<Station> stations;
        @SerializedName("status")
        public String status;
        @SerializedName("type")
        public String type;

        public SearchPlaceRes(Parcel parcel) {
            this.status = parcel.readString();
            this.type = parcel.readString();
            this.reason = parcel.readString();
            this.anid = parcel.readString();
            this.place = (Place) parcel.readParcelable(Place.class.getClassLoader());
            this.area = (Area) parcel.readParcelable(Area.class.getClassLoader());
            this.district = (District) parcel.readParcelable(District.class.getClassLoader());
            this.complex = (Complex) parcel.readParcelable(Complex.class.getClassLoader());
            this.nearbys = parcel.createTypedArrayList(Nearbys.CREATOR);
            this.stations = parcel.createTypedArrayList(Station.CREATOR);
            this.ad = (Advertisement) parcel.readParcelable(Advertisement.class.getClassLoader());
            this.geoFence = (GeoFence) parcel.readParcelable(GeoFence.class.getClassLoader());
            this.config = (SdkConfig) parcel.readParcelable(SdkConfig.class.getClassLoader());
            this.location = (Location) parcel.readParcelable(Location.class.getClassLoader());
            this.req_id = parcel.readString();
        }

        public int describeContents() {
            return 0;
        }

        public Advertisement getAd() {
            return this.ad;
        }

        public String getAnid() {
            return this.anid;
        }

        public Area getArea() {
            return this.area;
        }

        public Complex getComplex() {
            return this.complex;
        }

        public SdkConfig getConfig() {
            return this.config;
        }

        public District getDistrict() {
            return this.district;
        }

        public GeoFence getGeoFence() {
            return this.geoFence;
        }

        public Location getLocation() {
            return this.location;
        }

        public ArrayList<Nearbys> getNearbys() {
            return this.nearbys;
        }

        public Place getPlace() {
            return this.place;
        }

        public String getReason() {
            return this.reason;
        }

        public String getRequestId() {
            return this.req_id;
        }

        public ArrayList<Station> getStations() {
            return this.stations;
        }

        public String getStatus() {
            return this.status;
        }

        public String getType() {
            return this.type;
        }

        public void setAd(Advertisement advertisement) {
            this.ad = advertisement;
        }

        public void setAnid(String str) {
            this.anid = str;
        }

        public void setArea(Area area2) {
            this.area = area2;
        }

        public void setComplex(Complex complex2) {
            this.complex = complex2;
        }

        public void setDistrict(District district2) {
            this.district = district2;
        }

        public void setGeoFence(GeoFence geoFence2) {
            this.geoFence = geoFence2;
        }

        public void setLocation(Location location2) {
            this.location = location2;
        }

        public void setNearbys(ArrayList<Nearbys> arrayList) {
            this.nearbys = arrayList;
        }

        public void setPlace(Place place2) {
            this.place = place2;
        }

        public void setReason(String str) {
            this.reason = str;
        }

        public void setStations(ArrayList<Station> arrayList) {
            this.stations = arrayList;
        }

        public void setStatus(String str) {
            this.status = str;
        }

        public void setType(String str) {
            this.type = str;
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeString(this.status);
            parcel.writeString(this.type);
            parcel.writeString(this.reason);
            parcel.writeString(this.anid);
            parcel.writeParcelable(this.place, i);
            parcel.writeParcelable(this.area, i);
            parcel.writeParcelable(this.district, i);
            parcel.writeParcelable(this.complex, i);
            parcel.writeTypedList(this.nearbys);
            parcel.writeTypedList(this.stations);
            parcel.writeParcelable(this.ad, i);
            parcel.writeParcelable(this.geoFence, i);
            parcel.writeParcelable(this.config, i);
            parcel.writeParcelable(this.location, i);
            parcel.writeString(this.req_id);
        }
    }

    public static class Station implements Parcelable {
        public static final Creator<Station> CREATOR = new Creator<Station>() {
            public Station createFromParcel(Parcel parcel) {
                return new Station(parcel);
            }

            public Station[] newArray(int i) {
                return new Station[i];
            }
        };
        @SerializedName("client_code")
        public String client_code;
        @SerializedName("lat")
        public double lat;
        @SerializedName("lng")
        public double lng;
        @SerializedName("placename")
        public String placename;
        @SerializedName("scanned_fp")
        public ArrayList<WifiType> scanned_fp;

        public Station(Parcel parcel) {
            this.client_code = parcel.readString();
            this.placename = parcel.readString();
            this.lat = parcel.readDouble();
            this.lng = parcel.readDouble();
        }

        public int describeContents() {
            return 0;
        }

        public String getClient_code() {
            return this.client_code;
        }

        public double getLat() {
            return this.lat;
        }

        public double getLng() {
            return this.lng;
        }

        public String getPlacename() {
            return this.placename;
        }

        public ArrayList<WifiType> getScanned_fp() {
            return this.scanned_fp;
        }

        public void setClient_code(String str) {
            this.client_code = str;
        }

        public void setLat(double d) {
            this.lat = d;
        }

        public void setLng(double d) {
            this.lng = d;
        }

        public void setPlacename(String str) {
            this.placename = str;
        }

        public void setScanned_fp(ArrayList<WifiType> arrayList) {
            this.scanned_fp = arrayList;
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeString(this.client_code);
            parcel.writeString(this.placename);
            parcel.writeDouble(this.lat);
            parcel.writeDouble(this.lng);
        }
    }

    public class UplusLbmsRes {
        @SerializedName("lbs_lat")
        public String lbs_lat;
        @SerializedName("lbs_lng")
        public String lbs_lng;
        @SerializedName("pos_mode")
        public String pos_mode;
        @SerializedName("result_code")
        public String result_code;
        @SerializedName("result_msg")
        public String result_msg;

        public UplusLbmsRes() {
        }

        public String getLbs_lat() {
            return this.lbs_lat;
        }

        public String getLbs_lng() {
            return this.lbs_lng;
        }

        public String getPos_mode() {
            return this.pos_mode;
        }

        public String getResult_code() {
            return this.result_code;
        }

        public String getResult_msg() {
            return this.result_msg;
        }

        public void setLbs_lat(String str) {
            this.lbs_lat = str;
        }

        public void setLbs_lng(String str) {
            this.lbs_lng = str;
        }

        public void setPos_mode(String str) {
            this.pos_mode = str;
        }

        public void setResult_code(String str) {
            this.result_code = str;
        }

        public void setResult_msg(String str) {
            this.result_msg = str;
        }
    }

    public static class multiSdk implements Parcelable {
        public static final Creator<multiSdk> CREATOR = new Creator<multiSdk>() {
            public multiSdk createFromParcel(Parcel parcel) {
                return new multiSdk(parcel);
            }

            public multiSdk[] newArray(int i) {
                return new multiSdk[i];
            }
        };
        @SerializedName("cm_ch")
        public String cmCh;
        @SerializedName("code")
        public String code;

        public multiSdk(Parcel parcel) {
            this.cmCh = parcel.readString();
            this.code = parcel.readString();
        }

        public int describeContents() {
            return 0;
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeString(this.cmCh);
            parcel.writeString(this.code);
        }
    }
}