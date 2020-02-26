package com.loplat.placeengine.cloud;

import a.b.a.b.l;
import a.b.a.d.c;
import a.b.a.g.a;
import android.content.Context;
import androidx.annotation.NonNull;
import com.embrain.panelpower.IConstValue.SavedMoney;
import com.google.gson.annotations.SerializedName;
import com.loplat.placeengine.PlaceEngineBase;
import com.loplat.placeengine.wifi.WifiType;
import java.io.Serializable;
import java.util.List;

public class RequestMessage implements Serializable {
    public static final int CELL_TYPE_CDMA = 4;
    public static final int CELL_TYPE_GSM = 3;
    public static final int CELL_TYPE_LTE = 1;
    public static final int CELL_TYPE_UNKNOWN = 0;
    public static final int CELL_TYPE_WCDMA = 2;
    public static final String ENGINE_STATUS_GPS_OFF = "gps_off";
    public static final String ENGINE_STATUS_GPS_ON = "gps_on";
    public static final String ENGINE_STATUS_START = "start";
    public static final String ENGINE_STATUS_STOP = "stop";
    public static final String FEEDBACK_AD_RESULT = "feedback_ad_result";
    public static final String LEAVE_PLACE = "leave";
    public static final String SDK_EVENT_REGISTER_USER = "register_user";
    public static final String SDK_EVENT_STATE_LOG = "sdk_state";
    public static final String SDK_EVENT_UPDATE_CONFIG = "update_config";
    public static final String SEARCH_PLACE = "searchplace";
    public static final String SEARCH_PLACE_CELL = "searchplace_cell";
    public static final String SEARCH_PLACE_CHECK = "searchplace_check";
    public static final String SEARCH_PLACE_GPS = "searchplace_gps";
    public static final String SEARCH_PLACE_INTERNAL = "searchplace_internal";
    public static final String SEARCH_PLACE_UNKNOWN = "searchplace_unknown";
    public static final String SEARCH_PLACE_UNLOCK_SCREEN = "searchplace_unlockscreen";
    public static final String UPLUS_LBS_REQUEST = "uplus_lbs";
    public static final int VPN_CONNECTED = 1;
    public static final int VPN_NOT_CONNECTED = 0;

    public static class BaseMessage {
        @SerializedName("adid")
        public String adid;
        @SerializedName("anid")
        public String anid;
        @SerializedName("application")
        public String application;
        @SerializedName("client_id")
        public String client_id;
        @SerializedName("client_secret")
        public String client_secret;
        @SerializedName("echo_code")
        public String echo_code;
        @SerializedName("sdkversion")
        public String sdkversion;
        @SerializedName("type")
        public String type;

        public BaseMessage(Context context, String str) {
            setType(str);
            setClient_id(l.k);
            setClient_secret(l.l);
            setApplication(a.a(context));
            setSdkversion("2.0.8.2");
            setEcho_code(PlaceEngineBase.getEchoCode(context));
            setAdid(PlaceEngineBase.getUserAdId(context));
            setAnid(PlaceEngineBase.getANID(context));
        }

        public String getAdid() {
            return this.adid;
        }

        public String getAnid() {
            return this.anid;
        }

        public String getApplication() {
            return this.application;
        }

        public String getClient_id() {
            return this.client_id;
        }

        public String getClient_secret() {
            return this.client_secret;
        }

        public String getEcho_code() {
            return this.echo_code;
        }

        public String getSdkversion() {
            return this.sdkversion;
        }

        public String getType() {
            return this.type;
        }

        public void setAdid(String str) {
            if (str != null && !str.isEmpty()) {
                this.adid = str;
            }
        }

        public void setAnid(String str) {
            this.anid = str;
        }

        public void setApplication(String str) {
            this.application = str;
        }

        public void setClient_id(String str) {
            this.client_id = str;
        }

        public void setClient_secret(String str) {
            this.client_secret = str;
        }

        public void setEcho_code(String str) {
            this.echo_code = str;
        }

        public void setSdkversion(String str) {
            this.sdkversion = str;
        }

        public void setType(String str) {
            this.type = str;
        }
    }

    public static class CellEntity {
        @SerializedName("id")
        public Number cellId;
        @SerializedName("dbm")
        public Number dbm;
        @SerializedName("lac")
        public Number lac;
        @SerializedName("time")
        public long time;

        public Number getCellId() {
            return this.cellId;
        }

        public Number getDbm() {
            return this.dbm;
        }

        public Number getLac() {
            return this.lac;
        }

        public long getTime() {
            return this.time;
        }

        public void setCellId(Number number) {
            this.cellId = number;
        }

        public void setDbm(Number number) {
            this.dbm = number;
        }

        public void setLac(Number number) {
            this.lac = number;
        }

        public void setTime(long j) {
            this.time = j;
        }

        public String toString() {
            return String.format("[CID: %d][LAC: %d][Dbm: %d]", new Object[]{this.cellId, this.lac, this.dbm});
        }
    }

    public static class CellTowerInfo {
        @SerializedName("cell_id")
        public Number cellId;
        @SerializedName("cells")
        public List<CellEntity> cellList;
        @SerializedName("type")
        public int cellType;
        @SerializedName("dbm")
        public Number dbm;
        @SerializedName("ue_ip")
        public String ip;
        @SerializedName("lac")
        public Number lac;
        @SerializedName("lbs_lat")
        public double lbs_lat;
        @SerializedName("lbs_lng")
        public double lbs_lng;
        @SerializedName("lbs_mode")
        public String lbs_mode;
        @SerializedName("mcc")
        public Number mcc;
        @SerializedName("mnc")
        public Number mnc;
        @SerializedName("time")
        public long time;

        public Number getCellId() {
            return this.cellId;
        }

        public List<CellEntity> getCellList() {
            return this.cellList;
        }

        public int getCellType() {
            return this.cellType;
        }

        public Number getDbm() {
            return this.dbm;
        }

        public String getIp() {
            return this.ip;
        }

        public Number getLac() {
            return this.lac;
        }

        public double getLbsLat() {
            return this.lbs_lat;
        }

        public double getLbsLng() {
            return this.lbs_lng;
        }

        public String getLbsMode() {
            return this.lbs_mode;
        }

        public Number getMcc() {
            return this.mcc;
        }

        public Number getMnc() {
            return this.mnc;
        }

        public long getTime() {
            return this.time;
        }

        public void setCellId(Number number) {
            this.cellId = number;
        }

        public void setCellList(List<CellEntity> list) {
            this.cellList = list;
        }

        public void setCellType(int i) {
            this.cellType = i;
        }

        public void setDbm(Number number) {
            this.dbm = number;
        }

        public void setIp(String str) {
            this.ip = str;
        }

        public void setLac(Number number) {
            this.lac = number;
        }

        public void setLbsLat(double d) {
            this.lbs_lat = d;
        }

        public void setLbsLng(double d) {
            this.lbs_lng = d;
        }

        public void setLbsMode(String str) {
            this.lbs_mode = str;
        }

        public void setMcc(Number number) {
            this.mcc = number;
        }

        public void setMnc(Number number) {
            this.mnc = number;
        }

        public void setTime(long j) {
            this.time = j;
        }

        public String toString() {
            return String.format("[%d][CID: %d][LAC: %d][Dbm: %d]", new Object[]{Integer.valueOf(this.cellType), this.cellId, this.lac, this.dbm});
        }
    }

    public static class CheckPlaceInfo {
        @SerializedName("collector_id")
        public String collectorId;
        @SerializedName("fpid")
        public long fpId;
        @SerializedName("in_out")
        public String inOut;
        @SerializedName("pid")
        public long pid;

        public void setCollectorId(String str) {
            this.collectorId = str;
        }

        public void setFpId(long j) {
            this.fpId = j;
        }

        public void setInOut(String str) {
            this.inOut = str;
        }

        public void setPid(long j) {
            this.pid = j;
        }
    }

    public static class ClientInfo {
        @SerializedName("anid")
        public String anid;
        @SerializedName("application")
        public String application;
        @SerializedName("client_id")
        public String client_id;
        @SerializedName("client_secret")
        public String client_secret;
        @SerializedName("config_id")
        public int configID;
        @SerializedName("echo_code")
        public String echo_code;
        @SerializedName("enable_adnetwork")
        public boolean enableAdNetwork;
        @SerializedName("fp_scope")
        public Number fpScope;
        @SerializedName("sdkversion")
        public String sdkversion;
        @SerializedName("specialty")
        public Specialty specialty;
    }

    public static class Connection {
        @SerializedName("bssid")
        public String bssid;
        @SerializedName("frequency")
        public int frequency;
        @SerializedName("network")
        public String network;
        @SerializedName("rss")
        public int rss;
        @SerializedName("ssid")
        public String ssid;

        public String getBssid() {
            return this.bssid;
        }

        public int getFrequency() {
            return this.frequency;
        }

        public String getNetwork() {
            return this.network;
        }

        public int getRss() {
            return this.rss;
        }

        public String getSsid() {
            return this.ssid;
        }

        public void setBssid(String str) {
            this.bssid = str;
        }

        public void setFrequency(int i) {
            this.frequency = i;
        }

        public void setNetwork(String str) {
            this.network = str;
        }

        public void setRss(int i) {
            this.rss = i;
        }

        public void setSsid(String str) {
            this.ssid = str;
        }
    }

    public static class LeavePlaceReq extends BaseMessage {
        @SerializedName("category_code")
        public String category_code;
        @SerializedName("connection")
        public Connection connection;
        @SerializedName("duration_time")
        public long duration_time;
        @SerializedName("location")
        public Location location;
        @SerializedName("near")
        public long near;
        @SerializedName("placeid")
        public long placeid;
        @SerializedName("scan")
        public List<WifiType> scan;

        public LeavePlaceReq(Context context, String str) {
            super(context, str);
        }

        public Location getLocation() {
            return this.location;
        }

        public List<WifiType> getScan() {
            return this.scan;
        }

        public void setCategory_code(String str) {
            this.category_code = str;
        }

        public void setConnection(Connection connection2) {
            this.connection = connection2;
        }

        public void setDuration_time(long j) {
            this.duration_time = j;
        }

        public void setLocation(Location location2) {
            this.location = location2;
        }

        public void setNear(long j) {
            this.near = j;
        }

        public void setPlaceid(long j) {
            this.placeid = j;
        }

        public void setScan(List<WifiType> list) {
            this.scan = list;
        }
    }

    public static class Location {
        @SerializedName("accuracy")
        public float accuracy;
        @SerializedName("cell_info")
        public CellTowerInfo cellInfo;
        @SerializedName("lat")
        public double lat;
        @SerializedName("lng")
        public double lng;
        @SerializedName("provider")
        public String provider;
        @SerializedName("time")
        public long time;
        @SerializedName("vpn")
        public Number vpn;

        public Location() {
        }

        public float getAccuracy() {
            return this.accuracy;
        }

        public CellTowerInfo getCellInfo() {
            return this.cellInfo;
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

        public Number getVpn() {
            return this.vpn;
        }

        public void setAccuracy(float f) {
            this.accuracy = f;
        }

        public void setCellInfo(CellTowerInfo cellTowerInfo) {
            this.cellInfo = cellTowerInfo;
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

        public void setVpn(Number number) {
            this.vpn = number;
        }

        public Location(@NonNull android.location.Location location) {
            if (location != null) {
                this.lat = location.getLatitude();
                this.lng = location.getLongitude();
                this.provider = location.getProvider();
                this.accuracy = location.getAccuracy();
                this.time = location.getTime();
            }
        }
    }

    public static class MultiSearchPlaceReq {
        @SerializedName("client_list")
        public List<ClientInfo> clientInfoList;
        @SerializedName("connection")
        public Connection connection;
        @SerializedName("location")
        public Location location;
        @SerializedName("scan")
        public List<WifiType> scan;
    }

    public static class RegisterUserReq extends BaseMessage {
        @SerializedName("config_id")
        public int configID;

        public RegisterUserReq(Context context, String str) {
            super(context, str);
            this.configID = PlaceEngineBase.getConfigId(context);
        }
    }

    public static class ReportPlaceEngineStatus extends BaseMessage {
        @SerializedName("config_id")
        public int configID;
        @SerializedName("err_log")
        public String err_log;
        @SerializedName("state")
        public String state;
        @SerializedName("ui_mode")
        public String ui_mode;

        public ReportPlaceEngineStatus(Context context, String str) {
            super(context, str);
            this.configID = PlaceEngineBase.getConfigId(context);
        }

        public String getState() {
            return this.state;
        }

        public void setState(String str) {
            this.state = str;
        }
    }

    public static class SearchPlaceReq extends BaseMessage {
        @SerializedName("ad")
        public Number ad;
        @SerializedName("check_place")
        public CheckPlaceInfo checkPlaceInfo;
        @SerializedName("config_id")
        public int configID;
        @SerializedName("connection")
        public Connection connection;
        @SerializedName("fp_scope")
        public Number fpScope;
        @SerializedName("location")
        public Location location;
        @SerializedName("scan")
        public List<WifiType> scan;
        @SerializedName("specialty")
        public Specialty specialty;
        @SerializedName("user_activity")
        public String userActivity;

        public SearchPlaceReq(Context context, String str) {
            super(context, str);
            this.configID = PlaceEngineBase.getConfigId(context);
            if (!RequestMessage.SEARCH_PLACE_CELL.equals(str)) {
                int fpDataSource = PlaceEngineBase.getFpDataSource(context);
                if (fpDataSource != 0) {
                    this.fpScope = Integer.valueOf(fpDataSource);
                }
            }
            if (l.a(context, str) == 1) {
                this.ad = Integer.valueOf(1);
            }
        }

        public Connection getConnection() {
            return this.connection;
        }

        public Location getLocation() {
            return this.location;
        }

        public List<WifiType> getScan() {
            return this.scan;
        }

        public Specialty getSpecialty() {
            return this.specialty;
        }

        public void setCheckPlaceInfo(CheckPlaceInfo checkPlaceInfo2) {
            this.checkPlaceInfo = checkPlaceInfo2;
        }

        public void setConnection(Connection connection2) {
            this.connection = connection2;
        }

        public void setLocation(Location location2) {
            this.location = location2;
        }

        public void setScan(List<WifiType> list) {
            this.scan = list;
        }

        public void setSpecialty(Specialty specialty2) {
            this.specialty = specialty2;
        }

        public void setUserActivity(String str) {
            this.userActivity = str;
        }
    }

    public static class SendAdResultReq {
        @SerializedName("client_id")
        public String client_id;
        @SerializedName("msg_id")
        public int msg_id;
        @SerializedName("package")
        public String packageName;
        @SerializedName("result")
        public int result;
        @SerializedName("type")
        public String type;
        @SerializedName("ver")
        public String ver;

        public SendAdResultReq(String str) {
            this.type = str;
        }

        public String getClient_id() {
            return this.client_id;
        }

        public int getMsgID() {
            return this.msg_id;
        }

        public String getPackageName() {
            return this.packageName;
        }

        public int getResult() {
            return this.result;
        }

        public String getType() {
            return this.type;
        }

        public String getVer() {
            return this.ver;
        }

        public void setClient_id(String str) {
            this.client_id = str;
        }

        public void setMsgID(int i) {
            this.msg_id = i;
        }

        public void setPackageName(String str) {
            this.packageName = str;
        }

        public void setResult(int i) {
            this.result = i;
        }

        public void setType(String str) {
            this.type = str;
        }

        public void setVer(String str) {
            this.ver = str;
        }
    }

    public static class Specialty {
        @SerializedName("car_ap")
        public List<WifiType> car_ap;
        @SerializedName("next_station")
        public String next_station;
        @SerializedName("route")
        public List<String> route;
        @SerializedName("specialty_type")
        public String specialty_type;

        public void setCarAp(List<WifiType> list) {
            this.car_ap = list;
        }

        public void setNextStation(String str) {
            this.next_station = str;
        }

        public void setRoute(List<String> list) {
            this.route = list;
        }

        public void setSpecialty_type(String str) {
            this.specialty_type = str;
        }
    }

    public static class UpdateSdkConfigReq extends RegisterUserReq {
        public UpdateSdkConfigReq(Context context, String str) {
            super(context, str);
        }
    }

    public static class UplusLbmsReq {
        @SerializedName("api_key")
        public String apiKey;
        @SerializedName("client_id")
        public String clientId;
        @SerializedName("device_ip")
        public String deviceIp;
        @SerializedName("NW_INFO")
        public String nwInfo;
        @SerializedName("type")
        public String type;
        @SerializedName("version")
        public String version = "1.0";

        public UplusLbmsReq(Context context, String str) {
            this.type = str;
            this.apiKey = a.b.a.c.a.a(context, c.b, (String) "6", (String) "");
            this.clientId = a.b.a.c.a.a(context, c.b, (String) SavedMoney.GIVE_TP_TELCOIN, (String) "");
        }

        public String getType() {
            return this.type;
        }

        public void setDeviceIp(String str) {
            this.deviceIp = str;
        }

        public void setNwInfo(String str) {
            this.nwInfo = str;
        }

        public void setType(String str) {
            this.type = str;
        }
    }
}