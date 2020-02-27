package com.igaworks.dao;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import com.igaworks.core.AdvertisingIdClient.ADIDCallbackListener;
import com.igaworks.core.AdvertisingIdClient.AdInfo;
import com.igaworks.core.DeviceIDManger;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;

public class CoreIDDAO {
    public static final String IGAWORKS_CORE_ID_SP = "IgawCoreId";
    public static final String IGAWORKS_GOOGLE_ADID_KEY = "Igaw_google_advertising_id";
    public static final String IGAWORKS_PUID_KEY = "Igaw_puid";
    /* access modifiers changed from: private */
    public static boolean isIntializing = false;
    private static CoreIDDAO mGoogleAdIdDAO;
    private String IMEI = "";
    private SharedPreferences coreIdSP;
    private Editor editor_coreIdSP;
    private String googleAdId = "";

    private CoreIDDAO() {
    }

    public static CoreIDDAO getInstance() {
        if (mGoogleAdIdDAO == null) {
            mGoogleAdIdDAO = new CoreIDDAO();
        }
        return mGoogleAdIdDAO;
    }

    public void initialize(final Context context) {
        try {
            new Thread(new Runnable() {
                public void run() {
                    try {
                        if (CoreIDDAO.isIntializing) {
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "CoreIDDAO is called already.", 3, true);
                            return;
                        }
                        CoreIDDAO.isIntializing = true;
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "Initialzing CoreIDDAO", 3, true);
                        DeviceIDManger didManager = DeviceIDManger.getInstance(context);
                        Context context = context;
                        final Context context2 = context;
                        didManager.getAndroidADID(context, new ADIDCallbackListener() {
                            public void onResult(AdInfo adInfo) {
                                if (adInfo != null) {
                                    CoreIDDAO.this.setGoogleAdId(adInfo.getId());
                                    CoreIDDAO.this.setGoogleAdId2SP(context2, adInfo.getId());
                                } else {
                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, "CoreIDDAO > Fail to get google advertising ID >> adidInfo is Null ", 3, true);
                                }
                                CoreIDDAO.isIntializing = false;
                            }
                        });
                    } catch (Exception ex) {
                        CoreIDDAO.isIntializing = false;
                        ex.printStackTrace();
                    }
                }
            }).start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String getIMEIFromSP(Context context) {
        return getSharedPreferences(context).getString(IGAWORKS_PUID_KEY, "");
    }

    private void setIMEI2SP(Context context, String IMEI2) {
        getEditor(context).putString(IGAWORKS_PUID_KEY, IMEI2);
        getEditor(context).commit();
    }

    private String getGoogleAdIdFromSP(Context context) {
        return getSharedPreferences(context).getString(IGAWORKS_GOOGLE_ADID_KEY, "");
    }

    /* access modifiers changed from: private */
    public void setGoogleAdId2SP(Context context, String googleAdId2) {
        getEditor(context).putString(IGAWORKS_GOOGLE_ADID_KEY, googleAdId2);
        getEditor(context).commit();
    }

    private SharedPreferences getSharedPreferences(Context context) {
        if (this.coreIdSP == null) {
            this.coreIdSP = context.getSharedPreferences(IGAWORKS_CORE_ID_SP, 0);
        }
        return this.coreIdSP;
    }

    private Editor getEditor(Context context) {
        if (this.editor_coreIdSP == null) {
            this.editor_coreIdSP = getSharedPreferences(context).edit();
        }
        return this.editor_coreIdSP;
    }

    public String getIMEI(Context context) {
        if (this.IMEI.equals("")) {
            this.IMEI = getIMEIFromSP(context);
        }
        return this.IMEI;
    }

    public void setIMEI(Context context, String IMEI2) {
        this.IMEI = IMEI2;
        setIMEI2SP(context, IMEI2);
    }

    public String getGoogleAdId(Context context) {
        if (this.googleAdId.equals("")) {
            this.googleAdId = getGoogleAdIdFromSP(context);
        }
        if (this.googleAdId.equals("")) {
            initialize(context);
        }
        return this.googleAdId;
    }

    public void setGoogleAdId(String googleAdId2) {
        this.googleAdId = googleAdId2;
    }
}