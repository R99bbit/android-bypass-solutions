package com.igaworks.core;

import android.content.Context;
import android.provider.Settings.Secure;
import android.telephony.TelephonyManager;
import com.facebook.appevents.AppEventsConstants;
import com.igaworks.core.AdvertisingIdClient.ADIDCallbackListener;
import com.igaworks.core.AdvertisingIdClient.AdInfo;
import com.igaworks.dao.CoreIDDAO;
import io.fabric.sdk.android.services.common.CommonUtils;
import java.math.BigInteger;
import java.security.MessageDigest;

public class DeviceIDManger {
    private static DeviceIDManger singleton;
    public final int MD5_TYPE = 100;
    public final int SHA1_TYPE = 101;
    private AdInfo adidInfo;
    private Context context;

    private DeviceIDManger(Context context2) {
        this.context = context2;
    }

    public static DeviceIDManger getInstance(Context context2) {
        if (singleton == null) {
            singleton = new DeviceIDManger(context2);
        }
        return singleton;
    }

    public AdInfo getAdidInfo() {
        return this.adidInfo;
    }

    public void setAdidInfo(AdInfo adidInfo2) {
        this.adidInfo = adidInfo2;
    }

    public AdInfo getAndroidADID(Context context2, ADIDCallbackListener listener) {
        try {
            AdInfo cAdidInfo = AdvertisingIdClient.getAdvertisingIdInfo(context2, listener);
            if (cAdidInfo != null) {
                this.adidInfo = cAdidInfo;
            }
        } catch (Exception e) {
            if (e != null) {
                IgawLogger.Logging(context2, IgawConstant.QA_TAG, "getAndroidADID error : " + e.toString(), 3, true);
            }
        }
        return this.adidInfo;
    }

    public String getAESPuid(Context ctx) {
        String IMEI = CoreIDDAO.getInstance().getIMEI(ctx);
        if (IMEI.equals("")) {
            return "";
        }
        try {
            return AESGetPuid.encrypt(IMEI);
        } catch (Exception e) {
            IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "get AES puid ERROR : ", 0);
            e.printStackTrace();
            return "";
        }
    }

    public static String getAndroidId(Context context2) {
        try {
            return Secure.getString(context2.getContentResolver(), RequestParameter.ANDROID_ID);
        } catch (Exception e) {
            e.printStackTrace();
            return "unKnown";
        }
    }

    public static String getMd5Value(String s) {
        try {
            String md5 = new BigInteger(1, MessageDigest.getInstance(CommonUtils.MD5_INSTANCE).digest(s.getBytes())).toString(16);
            while (md5.length() < 32) {
                md5 = new StringBuilder(AppEventsConstants.EVENT_PARAM_VALUE_NO).append(md5).toString();
            }
            return md5;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public String getOpenUDID() {
        try {
            return OpenUDID_manager.getOpenUDID();
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String getSha1Value(String s) {
        try {
            MessageDigest sh = MessageDigest.getInstance(CommonUtils.SHA1_INSTANCE);
            sh.update(s.getBytes());
            byte[] byteData = sh.digest();
            StringBuffer sb = new StringBuffer();
            for (byte b : byteData) {
                sb.append(Integer.toString((b & 255) + 256, 16).substring(1));
            }
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public String getAndroidId(Context ctx, int type) {
        this.context = ctx;
        try {
            String android_id = Secure.getString(this.context.getContentResolver(), RequestParameter.ANDROID_ID);
            if (type == 100) {
                android_id = getMd5Value(android_id);
            } else if (type == 101) {
                android_id = getSha1Value(android_id);
            }
            return android_id;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public String getDeviceID(Context ctx, int type) {
        String deviceID = "";
        this.context = ctx;
        try {
            if (((TelephonyManager) this.context.getSystemService("phone")) == null || CoreIDDAO.getInstance().getIMEI(ctx).equals("")) {
                return null;
            }
            String id = CoreIDDAO.getInstance().getIMEI(ctx);
            if (type == 100) {
                deviceID = getMd5Value(id);
            } else if (type == 101) {
                deviceID = getSha1Value(id);
            }
            return deviceID;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public String getODIN1(Context context2) {
        try {
            return getSha1Value(Secure.getString(context2.getContentResolver(), RequestParameter.ANDROID_ID));
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public String getOPENUDID(String s, int type) {
        if (type == 100) {
            return getMd5Value(s);
        }
        if (type == 101) {
            return getSha1Value(s);
        }
        return "";
    }
}