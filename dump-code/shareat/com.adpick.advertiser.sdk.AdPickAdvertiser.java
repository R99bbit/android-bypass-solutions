package com.adpick.advertiser.sdk;

import android.content.Context;
import android.content.SharedPreferences.Editor;
import android.os.Build;
import android.os.Build.VERSION;
import android.provider.Settings.Secure;
import android.telephony.TelephonyManager;
import android.text.format.DateFormat;
import android.util.Log;
import com.facebook.appevents.AppEventsConstants;
import com.google.android.gms.ads.identifier.AdvertisingIdClient;
import com.google.android.gms.ads.identifier.AdvertisingIdClient.Info;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import com.igaworks.core.RequestParameter;
import com.nuvent.shareat.fragment.StoreDetailFragment;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

public class AdPickAdvertiser {
    private static String actype = "";
    /* access modifiers changed from: private */
    public static String debug = "NO";
    private static String extdata = "";

    public static void debug(String mode) {
        debug = mode;
    }

    public static void init(Context context, String secretkey) {
        try {
            String time = DateFormat.format("yy/MM/dd", System.currentTimeMillis()).toString();
            SetPref(context, "secretkey", secretkey);
            String installed = GetPref(context, "installed");
            String executedate = GetPref(context, "executedate");
            String certkey = GetPref(context, "certkey");
            String executecount = GetPref(context, "executecount");
            if (debug.equals("YES")) {
                Log.i("ADPICK", "adpick secretkey=" + secretkey + " installd=" + installed + " executedate=" + executedate + " executecount=" + executecount + " certkey=" + certkey + " time=" + time);
            }
            Log.i("ADPICK", "ADPICK initilized " + debug);
            if (installed.equals("done") && !executedate.equals(time)) {
                if (executecount == null || executecount.isEmpty()) {
                    executecount = AppEventsConstants.EVENT_PARAM_VALUE_NO;
                }
                int execnt = Integer.parseInt(executecount) + 1;
                SetPref(context, "executecount", Integer.toString(execnt));
                SetPref(context, "executedate", time);
                UserActivity(context, "execute", Integer.toString(execnt));
                if (debug.equals("YES")) {
                    Log.i("ADPICK", "executed " + Integer.toString(execnt));
                }
            }
            if (installed.equals("YES")) {
                UserActivity(context, "install", "");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String getSecretKey(Context context) {
        return GetPref(context, "secretkey");
    }

    public static void Logined(Context context) {
        String strlogincnt = GetPref(context, "login");
        Integer logincnt = Integer.valueOf(0);
        if (strlogincnt != null && !strlogincnt.isEmpty()) {
            logincnt = Integer.valueOf(Integer.parseInt(strlogincnt));
        }
        Integer logincnt2 = Integer.valueOf(logincnt.intValue() + 1);
        if (logincnt2.intValue() <= 10) {
            SetPref(context, "login", Integer.toString(logincnt2.intValue()));
            UserActivity(context, "login", "");
        }
    }

    public static void Action(Context context, String actype2) {
        String stractioncnt = GetPref(context, actype2);
        Integer actioncnt = Integer.valueOf(0);
        if (stractioncnt != null && !stractioncnt.isEmpty()) {
            actioncnt = Integer.valueOf(Integer.parseInt(stractioncnt));
        }
        Integer actioncnt2 = Integer.valueOf(actioncnt.intValue() + 1);
        if (actioncnt2.intValue() <= 10) {
            SetPref(context, actype2, Integer.toString(actioncnt2.intValue()));
            UserActivity(context, actype2, "");
        }
    }

    public static void Payment(Context context, String price) {
        if (!(price == null) && !price.isEmpty()) {
            UserActivity(context, StoreDetailFragment.SUB_TAB_NAME_PAYMENT, price);
        }
    }

    public static void UserActivity(Context context, String actype2, String strdata) {
        if (actype2.equals("install")) {
            SetPref(context, "installed", "done");
        }
        actype = actype2;
        if (strdata == null || strdata.isEmpty()) {
            extdata = "";
        } else {
            extdata = strdata;
        }
        SendToPodgateServer(context);
    }

    public static String makeHash(String s) {
        if (s == null || s.isEmpty()) {
            return null;
        }
        boolean z = false;
        try {
            MessageDigest m = MessageDigest.getInstance("SHA1");
            m.update(s.getBytes(), 0, s.length());
            return new BigInteger(1, m.digest()).toString(16);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return z;
        }
    }

    public static String MakeUrlString(Context context) {
        String strdevice = Build.DEVICE;
        String strproduct = Build.PRODUCT;
        String strversion = VERSION.RELEASE;
        String strlocale = context.getResources().getConfiguration().locale.getCountry();
        String url = new StringBuilder(String.valueOf(new StringBuilder(String.valueOf(new StringBuilder(String.valueOf(new StringBuilder(String.valueOf(new StringBuilder(String.valueOf(new StringBuilder(String.valueOf(new StringBuilder(String.valueOf(new StringBuilder(String.valueOf("http://pub.podgate.com/cpi.app?secret=" + GetPref(context, "secretkey"))).append("&device=").append(strdevice).toString())).append("&version=").append(strversion).toString())).append("&product=").append(strproduct).toString())).append("&locale=").append(strlocale).toString())).append("&app=").append(context.getApplicationContext().getPackageName()).toString())).append("&actype=").append(actype).toString())).append("&extdata=").append(extdata).toString())).append("&certkey=").append(GetPref(context, "certkey")).toString();
        if (debug.equals("YES")) {
            Log.i("adpick", "tracking : " + url);
        }
        return url;
    }

    public static String GetPref(Context context, String getkey) {
        return context.getSharedPreferences("PodgateADKeys", 0).getString(getkey, "");
    }

    public static void SetPref(Context context, String setkey, String value) {
        Editor ed = context.getSharedPreferences("PodgateADKeys", 0).edit();
        ed.putString(setkey, value);
        ed.commit();
    }

    public static void SendToPodgateServer(Context context) {
        new Thread(new Runnable(MakeUrlString(context), context) {
            String url;
            private final /* synthetic */ Context val$context;

            {
                this.val$context = r2;
                this.url = s;
            }

            public void run() {
                Info adInfo = null;
                try {
                    adInfo = AdvertisingIdClient.getAdvertisingIdInfo(this.val$context);
                } catch (GooglePlayServicesNotAvailableException | GooglePlayServicesRepairableException | IOException | IllegalStateException e) {
                }
                if (adInfo == null) {
                    this.url += "&user_token=" + AdPickAdvertiser.getUserToken(this.val$context);
                } else {
                    boolean isLAT = adInfo.isLimitAdTrackingEnabled();
                    String ad_id = adInfo.getId();
                    if (!isLAT || ad_id == null || ad_id.isEmpty()) {
                        this.url += "&ad_id=AdTrackingDisable";
                    } else {
                        this.url += "&ad_id=" + ad_id;
                    }
                }
                if (AdPickAdvertiser.debug.equals("YES")) {
                    Log.i("ADPICK", " SendToPodgateServer Tracking : " + this.url);
                }
                try {
                    URL url_obj = new URL(this.url);
                    try {
                        HttpURLConnection con = (HttpURLConnection) url_obj.openConnection();
                        con.setRequestMethod(HttpRequest.METHOD_GET);
                        con.connect();
                        int resCode = con.getResponseCode();
                        StringBuilder responseStringBuilder = new StringBuilder();
                        if (resCode == 200) {
                            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(con.getInputStream()));
                            while (true) {
                                String stringLine = bufferedReader.readLine();
                                if (stringLine == null) {
                                    break;
                                }
                                responseStringBuilder.append(new StringBuilder(String.valueOf(stringLine)).append(10).toString());
                            }
                            bufferedReader.close();
                            Log.i("ADPICK", "CODE= " + resCode + " , MESSAGE= " + responseStringBuilder.toString());
                        } else {
                            Log.i("ADPICK", "HTTP CONNECT ERROR CODE= " + resCode);
                        }
                        con.disconnect();
                        URL url2 = url_obj;
                    } catch (MalformedURLException e2) {
                        e = e2;
                        URL url3 = url_obj;
                    } catch (IOException e3) {
                        e = e3;
                        URL url4 = url_obj;
                        e.printStackTrace();
                    }
                } catch (MalformedURLException e4) {
                    e = e4;
                    e.printStackTrace();
                } catch (IOException e5) {
                    e = e5;
                    e.printStackTrace();
                }
            }
        }).start();
    }

    public static String getUserToken(Context context) {
        String user_token;
        String user_token2 = GetPref(context, "UserToken");
        if (user_token2 == null || user_token2.isEmpty()) {
            String deviceId = ((TelephonyManager) context.getSystemService("phone")).getDeviceId();
            if (deviceId != null) {
                user_token = makeHash(deviceId);
            } else {
                String androidId = Secure.getString(context.getContentResolver(), RequestParameter.ANDROID_ID);
                if (!"9774d56d682e549c".equals(androidId)) {
                    user_token = makeHash(androidId);
                } else {
                    user_token = makeHash(UUID.randomUUID().toString());
                }
            }
            SetPref(context, "UserToken", user_token);
            return user_token;
        }
        if (debug.equals("YES")) {
            Log.i("ADPICK", "UserToken already exists: " + user_token2);
        }
        return user_token2;
    }
}