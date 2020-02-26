package com.loplat.placeengine;

import a.a.a.a.a;
import android.content.Context;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import com.google.gson.annotations.SerializedName;
import com.loplat.placeengine.cloud.ResponseMessage.Advertisement;
import com.loplat.placeengine.cloud.ResponseMessage.GeoFence;
import com.loplat.placeengine.cloud.ResponseMessage.Nearbys;
import com.loplat.placeengine.wifi.WifiType;
import java.io.Serializable;
import java.util.ArrayList;

public class PlengiResponse implements Serializable {
    public static final String CONFIGURATION_UPDATED = "Configuration Updated";
    public static final String INVALID_SCAN_RESULTS = "Invalid Scan Results";
    public static final String LOCATION_ACQUISITION_FAIL = "Location Acquisition Fail";
    public static final String NETWORK_FAIL = "Network Fail";
    public static final String NOT_ALLOWED_CLIENT = "Not Allowed Client";
    public static final String NOT_ENTERED_CLIENT_ACCOUNT = "empty client ID or PW";
    public static final String START_SCAN = "Start Scan";
    public Advertisement advertisement;
    public Area area;
    public Complex complex;
    public District district;
    public String echo_code;
    public String errorReason;
    public GeoFence geoFence;
    public Location location;
    public ArrayList<Nearbys> nearbys;
    public Place place;
    public int placeEvent;
    public String requestId;
    public int result;
    public int type;

    public static class Area implements Parcelable {
        public static final Creator<Area> CREATOR = new Creator<Area>() {
            public Area createFromParcel(Parcel parcel) {
                return new Area(parcel);
            }

            public Area[] newArray(int i) {
                return new Area[i];
            }
        };
        @SerializedName("id")
        public int id;
        @SerializedName("lat")
        public double lat;
        @SerializedName("lng")
        public double lng;
        @SerializedName("name")
        public String name;
        @SerializedName("tag")
        public String tag;

        public Area() {
        }

        public int describeContents() {
            return 0;
        }

        public int getId() {
            return this.id;
        }

        public double getLat() {
            return this.lat;
        }

        public double getLng() {
            return this.lng;
        }

        public String getName() {
            return this.name;
        }

        public String getTag() {
            return this.tag;
        }

        public void setId(int i) {
            this.id = i;
        }

        public void setLat(double d) {
            this.lat = d;
        }

        public void setLng(double d) {
            this.lng = d;
        }

        public void setName(String str) {
            this.name = str;
        }

        public void setTag(String str) {
            this.tag = str;
        }

        public String toString() {
            if (this.name == null) {
                return "";
            }
            StringBuilder a2 = a.a("area: ");
            a2.append(this.name);
            a2.append(", tag: ");
            a2.append(this.tag);
            return a2.toString();
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeInt(this.id);
            parcel.writeString(this.name);
            parcel.writeString(this.tag);
            parcel.writeDouble(this.lat);
            parcel.writeDouble(this.lng);
        }

        public Area(Parcel parcel) {
            this.id = parcel.readInt();
            this.name = parcel.readString();
            this.tag = parcel.readString();
            this.lat = parcel.readDouble();
            this.lng = parcel.readDouble();
        }
    }

    public static class Complex implements Parcelable {
        public static final Creator<Complex> CREATOR = new Creator<Complex>() {
            public Complex createFromParcel(Parcel parcel) {
                return new Complex(parcel);
            }

            public Complex[] newArray(int i) {
                return new Complex[i];
            }
        };
        @SerializedName("branch_name")
        public String branch_name;
        @SerializedName("category")
        public String category;
        @SerializedName("category_code")
        public String category_code;
        @SerializedName("id")
        public int id;
        @SerializedName("name")
        public String name;

        public Complex() {
        }

        public int describeContents() {
            return 0;
        }

        public String getBranch_name() {
            return this.branch_name;
        }

        public String getCategory() {
            return this.category;
        }

        public String getCategory_code() {
            return this.category_code;
        }

        public int getId() {
            return this.id;
        }

        public String getName() {
            return this.name;
        }

        public void setBranch_name(String str) {
            this.branch_name = str;
        }

        public void setCategory(String str) {
            this.category = str;
        }

        public void setCategory_code(String str) {
            this.category_code = str;
        }

        public void setId(int i) {
            this.id = i;
        }

        public void setName(String str) {
            this.name = str;
        }

        public String toString() {
            if (this.name == null) {
                return "";
            }
            StringBuilder a2 = a.a("complex: ");
            a2.append(this.name);
            a2.append(", branch: ");
            a2.append(this.branch_name);
            a2.append(", category: ");
            a2.append(this.category);
            return a2.toString();
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeInt(this.id);
            parcel.writeString(this.name);
            parcel.writeString(this.branch_name);
            parcel.writeString(this.category);
            parcel.writeString(this.category_code);
        }

        public Complex(Parcel parcel) {
            this.id = parcel.readInt();
            this.name = parcel.readString();
            this.branch_name = parcel.readString();
            this.category = parcel.readString();
            this.category_code = parcel.readString();
        }
    }

    public static class District implements Parcelable {
        public static final Creator<District> CREATOR = new Creator<District>() {
            public District createFromParcel(Parcel parcel) {
                return new District(parcel);
            }

            public District[] newArray(int i) {
                return new District[i];
            }
        };
        @SerializedName("lv0_code")
        public String lv0Code;
        @SerializedName("lv1_code")
        public String lv1Code;
        @SerializedName("lv1_name")
        public String lv1Name;
        @SerializedName("lv2_code")
        public String lv2Code;
        @SerializedName("lv2_name")
        public String lv2Name;
        @SerializedName("lv3_code")
        public String lv3Code;
        @SerializedName("lv3_name")
        public String lv3Name;

        public District() {
        }

        public int describeContents() {
            return 0;
        }

        public String getLv0Code() {
            return this.lv0Code;
        }

        public String getLv1Code() {
            return this.lv1Code;
        }

        public String getLv1Name() {
            return this.lv1Name;
        }

        public String getLv2Code() {
            return this.lv2Code;
        }

        public String getLv2Name() {
            return this.lv2Name;
        }

        public String getLv3Code() {
            return this.lv3Code;
        }

        public String getLv3Name() {
            return this.lv3Name;
        }

        public void setLv0Code(String str) {
            this.lv0Code = str;
        }

        public void setLv1Code(String str) {
            this.lv1Code = str;
        }

        public void setLv1Name(String str) {
            this.lv1Name = str;
        }

        public void setLv2Code(String str) {
            this.lv2Code = str;
        }

        public void setLv2Name(String str) {
            this.lv2Name = str;
        }

        public void setLv3Code(String str) {
            this.lv3Code = str;
        }

        public void setLv3Name(String str) {
            this.lv3Name = str;
        }

        public String toString() {
            StringBuilder a2 = a.a("District{lv0Code='");
            a2.append(this.lv0Code);
            a2.append('\'');
            a2.append(", lv1Code='");
            a2.append(this.lv1Code);
            a2.append('\'');
            a2.append(", lv1Name='");
            a2.append(this.lv1Name);
            a2.append('\'');
            a2.append(", lv2Code='");
            a2.append(this.lv2Code);
            a2.append('\'');
            a2.append(", lv2Name='");
            a2.append(this.lv2Name);
            a2.append('\'');
            a2.append(", lv3Code='");
            a2.append(this.lv3Code);
            a2.append('\'');
            a2.append(", lv3Name='");
            a2.append(this.lv3Name);
            a2.append('\'');
            a2.append('}');
            return a2.toString();
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeString(this.lv0Code);
            parcel.writeString(this.lv1Code);
            parcel.writeString(this.lv1Name);
            parcel.writeString(this.lv2Code);
            parcel.writeString(this.lv2Name);
            parcel.writeString(this.lv3Code);
            parcel.writeString(this.lv3Name);
        }

        public District(Parcel parcel) {
            this.lv0Code = parcel.readString();
            this.lv1Code = parcel.readString();
            this.lv1Name = parcel.readString();
            this.lv2Code = parcel.readString();
            this.lv2Name = parcel.readString();
            this.lv3Code = parcel.readString();
            this.lv3Name = parcel.readString();
        }
    }

    public static class Location implements Parcelable {
        public static final Creator<Location> CREATOR = new Creator<Location>() {
            public Location createFromParcel(Parcel parcel) {
                return new Location(parcel);
            }

            public Location[] newArray(int i) {
                return new Location[i];
            }
        };
        @SerializedName("accuracy")
        public float accuracy;
        @SerializedName("cid")
        public int cellId;
        @SerializedName("floor")
        public int floor = 1;
        @SerializedName("lat")
        public double lat = 0.0d;
        @SerializedName("lng")
        public double lng = 0.0d;
        @SerializedName("provider")
        public String provider;
        @SerializedName("time")
        public long time = 0;

        public Location() {
        }

        public int describeContents() {
            return 0;
        }

        public float getAccuracy() {
            return this.accuracy;
        }

        public int getCellId() {
            return this.cellId;
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

        public String getProvider() {
            return this.provider;
        }

        public long getTime() {
            return this.time;
        }

        public void setAccuracy(float f) {
            this.accuracy = f;
        }

        public void setCellId(int i) {
            this.cellId = i;
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

        public void setProvider(String str) {
            this.provider = str;
        }

        public void setTime(long j) {
            this.time = j;
        }

        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(this.lat);
            sb.append(", ");
            sb.append(this.lng);
            sb.append(", ");
            sb.append(this.floor);
            sb.append(", ");
            sb.append(this.accuracy);
            sb.append(", ");
            sb.append(this.provider);
            return sb.toString();
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeDouble(this.lat);
            parcel.writeDouble(this.lng);
            parcel.writeInt(this.floor);
            parcel.writeFloat(this.accuracy);
            parcel.writeString(this.provider);
            parcel.writeLong(this.time);
            parcel.writeInt(this.cellId);
        }

        public Location(Parcel parcel) {
            this.lat = parcel.readDouble();
            this.lng = parcel.readDouble();
            this.floor = parcel.readInt();
            this.accuracy = parcel.readFloat();
            this.provider = parcel.readString();
            this.time = parcel.readLong();
            this.cellId = parcel.readInt();
        }
    }

    public class MonitoringType {
        public static final int STAY = 0;
        public static final int TRACKING = 1;

        public MonitoringType() {
        }
    }

    public static class Place implements Parcelable {
        public static final Creator<Place> CREATOR = new Creator<Place>() {
            public Place createFromParcel(Parcel parcel) {
                return new Place(parcel);
            }

            public Place[] newArray(int i) {
                return new Place[i];
            }
        };
        @SerializedName("accuracy")
        public float accuracy;
        @SerializedName("address")
        public String address;
        @SerializedName("address_road")
        public String address_road;
        public Advertisement advertisement;
        @SerializedName("category")
        public String category;
        @SerializedName("category_code")
        public String category_code;
        @SerializedName("client_code")
        public String client_code;
        @SerializedName("distance")
        public int distance;
        @SerializedName("duration_time")
        public long duration_time;
        @SerializedName("floor")
        public int floor;
        @SerializedName("fpid")
        public long fpid;
        @SerializedName("lat")
        public double lat;
        @SerializedName("lng")
        public double lng;
        @SerializedName("loplat_id")
        public long loplatid;
        @SerializedName("name")
        public String name;
        @SerializedName("placename")
        public String placename;
        @SerializedName("post")
        public String post_code;
        @SerializedName("scanned_fp")
        public ArrayList<WifiType> scanned_fp;
        @SerializedName("status")
        public String status;
        @SerializedName("tags")
        public String tags;
        @SerializedName("threshold")
        public float threshold;

        public Place() {
        }

        public int describeContents() {
            return 0;
        }

        public float getAccuracy() {
            return this.accuracy;
        }

        public String getAddress() {
            return this.address;
        }

        public String getAddress_road() {
            return this.address_road;
        }

        public String getCategory() {
            return this.category;
        }

        public String getCategory_code() {
            return this.category_code;
        }

        public String getClient_code() {
            return this.client_code;
        }

        public int getDistance() {
            return this.distance;
        }

        public long getDuration_time() {
            return this.duration_time;
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

        public String getName() {
            return this.name;
        }

        public String getPlacename() {
            return this.placename;
        }

        public String getPost_code() {
            return this.post_code;
        }

        public ArrayList<WifiType> getScanned_fp() {
            return this.scanned_fp;
        }

        public String getStatus() {
            return this.status;
        }

        public String getTags() {
            return this.tags;
        }

        public float getThreshold() {
            return this.threshold;
        }

        public void setAccuracy(float f) {
            this.accuracy = f;
        }

        public void setAddress(String str) {
            this.address = str;
        }

        public void setAddress_road(String str) {
            this.address_road = str;
        }

        public void setCategory(String str) {
            this.category = str;
        }

        public void setCategory_code(String str) {
            this.category_code = str;
        }

        public void setClient_code(String str) {
            this.client_code = str;
        }

        public void setDistance(int i) {
            this.distance = i;
        }

        public void setDuration_time(long j) {
            this.duration_time = j;
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

        public void setName(String str) {
            this.name = str;
        }

        public void setPlacename(String str) {
            this.placename = str;
        }

        public void setPost_code(String str) {
            this.post_code = str;
        }

        public void setScanned_fp(ArrayList<WifiType> arrayList) {
            this.scanned_fp = arrayList;
        }

        public void setStatus(String str) {
            this.status = str;
        }

        public void setTags(String str) {
            this.tags = str;
        }

        public void setThreshold(float f) {
            this.threshold = f;
        }

        public String toString() {
            if (this.loplatid == 0) {
                return "";
            }
            StringBuilder a2 = a.a("placename: ");
            a2.append(this.name);
            a2.append(", accuracy: ");
            a2.append(this.accuracy);
            a2.append(", lat: ");
            a2.append(this.lat);
            a2.append(", lng: ");
            a2.append(this.lng);
            a2.append(", client_code: ");
            a2.append(this.client_code);
            a2.append(", loplatid: ");
            a2.append(this.loplatid);
            return a2.toString();
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeString(this.status);
            parcel.writeLong(this.loplatid);
            parcel.writeString(this.placename);
            parcel.writeString(this.name);
            parcel.writeString(this.tags);
            parcel.writeInt(this.floor);
            parcel.writeString(this.category);
            parcel.writeString(this.category_code);
            parcel.writeDouble(this.lat);
            parcel.writeDouble(this.lng);
            parcel.writeFloat(this.accuracy);
            parcel.writeFloat(this.threshold);
            parcel.writeString(this.client_code);
            parcel.writeInt(this.distance);
            parcel.writeString(this.address);
            parcel.writeString(this.address_road);
            parcel.writeString(this.post_code);
            parcel.writeLong(this.duration_time);
            parcel.writeLong(this.fpid);
        }

        public Place(Parcel parcel) {
            this.status = parcel.readString();
            this.loplatid = parcel.readLong();
            this.placename = parcel.readString();
            this.name = parcel.readString();
            this.tags = parcel.readString();
            this.floor = parcel.readInt();
            this.category = parcel.readString();
            this.category_code = parcel.readString();
            this.lat = parcel.readDouble();
            this.lng = parcel.readDouble();
            this.accuracy = parcel.readFloat();
            this.threshold = parcel.readFloat();
            this.client_code = parcel.readString();
            this.distance = parcel.readInt();
            this.address = parcel.readString();
            this.address_road = parcel.readString();
            this.post_code = parcel.readString();
            this.duration_time = parcel.readLong();
            this.fpid = parcel.readLong();
        }
    }

    public class PlaceEvent {
        public static final int ENTER = 1;
        public static final int LEAVE = 2;
        public static final int NEARBY = 3;
        public static final int NOT_AVAILABLE = 0;

        public PlaceEvent() {
        }
    }

    public class PlaceStatus {
        public static final int MOVE = 0;
        public static final int STAY = 2;

        public PlaceStatus() {
        }
    }

    public class ResponseType {
        public static final int CELL_LOCATION_EVENT = 5;
        public static final int LOGGING = 9;
        public static final int PLACE = 1;
        public static final int PLACE_EVENT = 2;
        public static final int PLACE_TRACKING = 3;

        public ResponseType() {
        }
    }

    public class Result {
        public static final int ALREADY_STARTED = -8;
        public static final int ERROR_CLOUD_ACCESS = -4;
        public static final int FAIL = -1;
        public static final int FAIL_CONSUMER_STATE = -9;
        public static final int FAIL_INTERNET_UNAVAILABLE = -5;
        public static final int FAIL_WIFI_SCAN_UNAVAILABLE = -6;
        public static final int NETWORK_FAIL = -3;
        public static final int NOT_INITIALIZED = -10;
        public static final int NOT_SUPPORTED_OS_VERSION = -7;
        public static final int PENDING = -2;
        public static final int SUCCESS = 0;

        public Result() {
        }
    }

    public static class Visit {
        @SerializedName("enter")
        public long enter;
        @SerializedName("leave")
        public long leave;
        @SerializedName("placeid")
        public long placeid;
        @SerializedName("visitid")
        public int visitid;

        public Visit(int i, long j, long j2, long j3) {
            this.visitid = i;
            this.placeid = j;
            this.enter = j2;
            this.leave = j3;
        }
    }

    public PlengiResponse() {
    }

    public PlengiResponse(Context context) {
        this.echo_code = PlaceEngineBase.getEchoCode(context);
    }
}