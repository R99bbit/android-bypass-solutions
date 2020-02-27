package com.igaworks;

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.net.Uri;
import android.os.Bundle;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.dao.ReferralInfoDAO;
import java.net.URLDecoder;
import java.util.Iterator;
import java.util.Set;

public class IgawReceiver extends BroadcastReceiver {
    private final String REFERRER = "referrer";
    private int conversion_key = -1;
    private long session_no = -1;

    public void onReceive(Context context, Intent intent) {
        try {
            String action = intent.getAction();
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawReceiver onReceive() >> action : " + action, 3);
            if (action.equals("com.android.vending.INSTALL_REFERRER")) {
                Bundle parameter = intent.getExtras();
                String wholeParam = "";
                if (parameter != null) {
                    Set<String> referrerParams = parameter.keySet();
                    if (referrerParams != null) {
                        for (String item : referrerParams) {
                            if (item.equals("referrer")) {
                                wholeParam = new StringBuilder(String.valueOf(wholeParam)).append(parameter.getString(item)).toString();
                            }
                        }
                    }
                } else {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawReceiver onReceive() >> referrer paramter is null >> wholeParam is empty", 3);
                }
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawReceiver onReceive() >> referrer param = " + wholeParam, 3);
                if (parameter == null || !parameter.containsKey("referrer")) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawReceiver onReceive() >> referrer paramter is null", 3);
                } else {
                    String referrer = parameter.getString("referrer");
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawReceiver onReceive() >> referrer : " + referrer, 3);
                    try {
                        String decodedReferrer = URLDecoder.decode(referrer, "utf-8");
                        if (decodedReferrer.contains("%3D") || decodedReferrer.contains("%26")) {
                            decodedReferrer = decodedReferrer.replace("%3D", "=").replace("%26", "&");
                        }
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawReceiver onReceive() >> decodedReferrer : " + decodedReferrer, 3);
                        Uri referrerUri = Uri.parse("http://referrer.ad-brix.com?" + decodedReferrer);
                        String ckStr = null;
                        try {
                            ckStr = referrerUri.getQueryParameter("ck");
                        } catch (Exception e) {
                        }
                        if (ckStr != null) {
                            try {
                                this.conversion_key = Integer.parseInt(ckStr);
                            } catch (Exception e2) {
                                this.conversion_key = -1;
                            }
                        }
                        String snStr = null;
                        try {
                            snStr = referrerUri.getQueryParameter("sn");
                        } catch (Exception e3) {
                        }
                        if (snStr != null) {
                            try {
                                this.session_no = Long.parseLong(snStr);
                            } catch (Exception e4) {
                                this.session_no = -1;
                            }
                        }
                        if (this.conversion_key > 0) {
                            ReferralInfoDAO.setReferralInfo(context, this.conversion_key, this.session_no, wholeParam);
                        }
                    } catch (Exception e5) {
                        e5.printStackTrace();
                    }
                }
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawReceiver onReceive() >> Forward INSTALL_REFERRER start...", 3, false);
                try {
                    PackageManager packageManager = context.getPackageManager();
                    ComponentName componentName = new ComponentName(context, "com.igaworks.IgawReceiver");
                    ActivityInfo ai = packageManager.getReceiverInfo(componentName, 128);
                    if (ai != null) {
                        Bundle bundle = ai.metaData;
                        if (bundle != null) {
                            Set<String> keys = bundle.keySet();
                            if (keys != null) {
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawReceiver onReceive() >> Forward INSTALL_REFERRER count : " + keys.size(), 3, false);
                                Iterator<String> it = keys.iterator();
                                if (it != null) {
                                    while (it.hasNext()) {
                                        String v = bundle.getString(it.next());
                                        ((BroadcastReceiver) Class.forName(v).newInstance()).onReceive(context, intent);
                                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawReceiver onReceive() >> Forward INSTALL_REFERRER to " + v, 3, false);
                                    }
                                }
                            }
                        }
                    }
                } catch (NameNotFoundException e6) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawReceiver onReceive() >> No receiver to forward", 2, false);
                } catch (InstantiationException e7) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawReceiver onReceive() >> Forward INSTALL_REFERRER error : " + e7.toString(), 1, false);
                } catch (IllegalAccessException e8) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawReceiver onReceive() >> Forward INSTALL_REFERRER error : " + e8.toString(), 1, false);
                } catch (ClassNotFoundException e9) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawReceiver onReceive() >> Forward INSTALL_REFERRER error : " + e9.toString(), 1, false);
                } catch (Exception e10) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawReceiver onReceive() >> Forward INSTALL_REFERRER error : " + e10.toString(), 1, false);
                }
            }
        } catch (Exception e11) {
            e11.printStackTrace();
        }
    }
}