package com.loplat.placeengine.a;

import android.content.Context;
import android.content.SharedPreferences.Editor;
import android.location.Location;
import android.widget.Toast;
import com.google.firebase.analytics.FirebaseAnalytics.Param;
import com.kakao.auth.helper.ServerProtocol;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.loplat.placeengine.a;
import com.loplat.placeengine.d.d;
import com.loplat.placeengine.location.LocationMonitorService;
import com.loplat.placeengine.utils.LoplatLogger;
import java.util.ArrayList;
import java.util.List;
import org.jboss.netty.handler.codec.rtsp.RtspHeaders.Values;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* compiled from: CloudManager */
public class b {
    public static void a(Context context, List<d> scanResults) {
        a cloud = new a(context);
        JSONObject jsonObject = new JSONObject();
        try {
            jsonObject.put(KakaoTalkLinkProtocol.ACTION_TYPE, "searchplace");
            jsonObject.put("client_id", d(context));
            jsonObject.put("client_secret", e(context));
            jsonObject.put(ServerProtocol.DEVICE_ID_PARAM_NAME, a.o(context));
            jsonObject.put("application", com.loplat.placeengine.c.a.q(context));
            jsonObject.put("sdkversion", com.loplat.placeengine.c.a.a());
            String adid = a.p(context);
            if (adid != null || (adid != null && !adid.equals(""))) {
                jsonObject.put("adid", adid);
            }
            Location location = LocationMonitorService.b(context);
            if (location != null) {
                JSONObject locObject = new JSONObject();
                locObject.put("lat", location.getLatitude());
                locObject.put("lng", location.getLongitude());
                locObject.put(Values.TIME, location.getTime());
                locObject.put("accuracy", (double) location.getAccuracy());
                locObject.put("provider", location.getProvider());
                ArrayList<Integer> mobileCodes = com.loplat.placeengine.c.a.r(context);
                if (mobileCodes != null && mobileCodes.size() > 1) {
                    locObject.put("mcc", mobileCodes.get(0));
                    locObject.put("mnc", mobileCodes.get(1));
                }
                jsonObject.put(Param.LOCATION, locObject);
            }
            JSONArray jsonArray = new JSONArray();
            for (d foot : scanResults) {
                JSONObject wifiObject = new JSONObject();
                wifiObject.put("bssid", foot.a);
                wifiObject.put("ssid", foot.b);
                wifiObject.put("rss", foot.c);
                wifiObject.put("frequency", foot.d);
                jsonArray.put(wifiObject);
            }
            jsonObject.put("scan", jsonArray);
            JSONObject networkInfo = com.loplat.placeengine.c.a.s(context);
            if (!networkInfo.isNull("network")) {
                jsonObject.put("connection", networkInfo);
            }
        } catch (JSONException e) {
            e.printStackTrace();
        } catch (NullPointerException e2) {
            e2.printStackTrace();
        }
        LoplatLogger.printLog("searchplace" + jsonObject.toString());
        cloud.a("searchplace", jsonObject.toString());
    }

    public static void b(Context context, List<d> scanResults) {
        a cloud = new a(context);
        JSONObject jsonObject = new JSONObject();
        try {
            jsonObject.put(KakaoTalkLinkProtocol.ACTION_TYPE, "searchplace_internal");
            jsonObject.put("client_id", d(context));
            jsonObject.put("client_secret", e(context));
            jsonObject.put(ServerProtocol.DEVICE_ID_PARAM_NAME, a.o(context));
            jsonObject.put("application", com.loplat.placeengine.c.a.q(context));
            jsonObject.put("sdkversion", com.loplat.placeengine.c.a.a());
            String adId = a.p(context);
            if (adId != null || (adId != null && !adId.equals(""))) {
                jsonObject.put("adid", adId);
            }
            Location location = LocationMonitorService.b(context);
            if (location != null) {
                JSONObject locObject = new JSONObject();
                locObject.put("lat", location.getLatitude());
                locObject.put("lng", location.getLongitude());
                locObject.put(Values.TIME, location.getTime());
                locObject.put("accuracy", (double) location.getAccuracy());
                locObject.put("provider", location.getProvider());
                ArrayList<Integer> mobileCodes = com.loplat.placeengine.c.a.r(context);
                if (mobileCodes != null && mobileCodes.size() > 1) {
                    locObject.put("mcc", mobileCodes.get(0));
                    locObject.put("mnc", mobileCodes.get(1));
                }
                jsonObject.put(Param.LOCATION, locObject);
            }
            JSONArray jsonArray = new JSONArray();
            for (d foot : scanResults) {
                JSONObject wifiObject = new JSONObject();
                wifiObject.put("bssid", foot.a);
                wifiObject.put("ssid", foot.b);
                wifiObject.put("rss", foot.c);
                wifiObject.put("frequency", foot.d);
                jsonArray.put(wifiObject);
            }
            jsonObject.put("scan", jsonArray);
            JSONObject networkInfo = com.loplat.placeengine.c.a.s(context);
            if (!networkInfo.isNull("network")) {
                jsonObject.put("connection", networkInfo);
            }
        } catch (JSONException e) {
            e.printStackTrace();
        } catch (NullPointerException e2) {
            e2.printStackTrace();
        }
        LoplatLogger.printLog("searchplace_internal" + jsonObject.toString());
        cloud.a("searchplace", jsonObject.toString());
    }

    public static void a(Context context, long loplatid) {
        a cloud = new a(context);
        JSONObject jsonObject = new JSONObject();
        try {
            jsonObject.put(KakaoTalkLinkProtocol.ACTION_TYPE, "leave");
            jsonObject.put("client_id", d(context));
            jsonObject.put("client_secret", e(context));
            jsonObject.put(ServerProtocol.DEVICE_ID_PARAM_NAME, a.o(context));
            String adId = a.p(context);
            if (adId != null || (adId != null && !adId.equals(""))) {
                jsonObject.put("adid", adId);
            }
            jsonObject.put("placeid", loplatid);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        LoplatLogger.printLog("leave placeevent" + jsonObject.toString());
        cloud.a("placeevent", jsonObject.toString());
    }

    public static void c(Context context, List<d> scanResults) {
        a cloud = new a(context);
        JSONObject jsonObject = new JSONObject();
        try {
            jsonObject.put(KakaoTalkLinkProtocol.ACTION_TYPE, "getuuidp");
            jsonObject.put("client_id", d(context));
            jsonObject.put("client_secret", e(context));
            JSONArray jsonArray = new JSONArray();
            for (d foot : scanResults) {
                JSONObject wifiObject = new JSONObject();
                wifiObject.put("bssid", foot.a);
                wifiObject.put("ssid", foot.b);
                wifiObject.put("rss", foot.c);
                wifiObject.put("frequency", foot.d);
                jsonArray.put(wifiObject);
            }
            jsonObject.put("scan", jsonArray);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        cloud.a("uuidp", jsonObject.toString());
    }

    public static void d(Context context, List<d> scanResults) {
        if (scanResults.size() == 0) {
            Toast.makeText(context, "No wifi scan", 1).show();
            return;
        }
        a cloud = new a(context);
        JSONObject jsonObject = new JSONObject();
        try {
            jsonObject.put(KakaoTalkLinkProtocol.ACTION_TYPE, "startcolocate");
            jsonObject.put("client_id", d(context));
            jsonObject.put("client_secret", e(context));
            jsonObject.put("userid", c(context));
            JSONArray jsonArray = new JSONArray();
            for (d foot : scanResults) {
                JSONObject wifiObject = new JSONObject();
                wifiObject.put("bssid", foot.a);
                wifiObject.put("ssid", foot.b);
                wifiObject.put("rss", foot.c);
                wifiObject.put("frequency", foot.d);
                jsonArray.put(wifiObject);
            }
            jsonObject.put("scan", jsonArray);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        cloud.a("colocate", jsonObject.toString());
    }

    public static void a(Context context) {
        a cloud = new a(context);
        JSONObject jsonObject = new JSONObject();
        try {
            jsonObject.put(KakaoTalkLinkProtocol.ACTION_TYPE, "getcolocate");
            jsonObject.put("client_id", d(context));
            jsonObject.put("client_secret", e(context));
            jsonObject.put("userid", c(context));
        } catch (JSONException e) {
            e.printStackTrace();
        }
        cloud.a("colocate", jsonObject.toString());
    }

    public static void b(Context context) {
        a cloud = new a(context);
        JSONObject jsonObject = new JSONObject();
        try {
            jsonObject.put(KakaoTalkLinkProtocol.ACTION_TYPE, "stopcolocate");
            jsonObject.put("client_id", d(context));
            jsonObject.put("client_secret", e(context));
            jsonObject.put("userid", c(context));
        } catch (JSONException e) {
            e.printStackTrace();
        }
        cloud.a("colocate", jsonObject.toString());
    }

    public static void a(Context context, String userId, String userAdId) {
        if (c(context) == 0) {
            b(context, System.currentTimeMillis());
        }
        String email = userId;
        String adId = userAdId;
        a cloud = new a(context);
        JSONObject jsonObject = new JSONObject();
        try {
            jsonObject.put(KakaoTalkLinkProtocol.ACTION_TYPE, "registeruser");
            jsonObject.put("client_id", d(context));
            jsonObject.put("client_secret", e(context));
            jsonObject.put("userid", c(context));
            jsonObject.put("email", email);
            if (adId != null || (adId != null && !adId.equals(""))) {
                jsonObject.put("adid", adId);
            }
        } catch (JSONException e) {
            e.printStackTrace();
        } catch (NullPointerException e2) {
            e2.printStackTrace();
        }
        LoplatLogger.printLog("registeruser" + jsonObject.toString());
        cloud.a("colocate", jsonObject.toString());
    }

    public static void b(Context context, long userid) {
        try {
            Editor editor = context.getSharedPreferences("CloudManager", 0).edit();
            editor.putLong("userid", userid);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set user ID error: " + e);
        }
    }

    public static long c(Context context) {
        long userId = 0;
        try {
            return context.getSharedPreferences("CloudManager", 0).getLong("userid", 0);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get user ID error: " + e);
            return userId;
        }
    }

    public static void a(Context context, String clientid) {
        try {
            Editor editor = context.getSharedPreferences("CloudManager", 0).edit();
            editor.putString("clientid", clientid);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set client ID error: " + e);
        }
    }

    public static String d(Context context) {
        String clientId = null;
        try {
            return context.getSharedPreferences("CloudManager", 0).getString("clientid", null);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get client ID error: " + e);
            return clientId;
        }
    }

    public static void b(Context context, String clientsecret) {
        try {
            Editor editor = context.getSharedPreferences("CloudManager", 0).edit();
            editor.putString("clientsecret", clientsecret);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set client secret error: " + e);
        }
    }

    public static String e(Context context) {
        String secret = null;
        try {
            return context.getSharedPreferences("CloudManager", 0).getString("clientsecret", null);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get client secret error: " + e);
            return secret;
        }
    }
}