package com.igaworks.dao;

import android.content.Context;
import android.os.Build;
import android.os.Environment;
import android.util.Pair;
import com.igaworks.core.AdvertisingIdClient.ADIDCallbackListener;
import com.igaworks.core.AdvertisingIdClient.AdInfo;
import com.igaworks.core.DeviceIDManger;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;
import com.igaworks.cpe.ConditionChecker;
import com.igaworks.util.CommonHelper;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class IgawSignatureManager {
    private static final String AKEY = "build.sign=";
    private static final String PKG1 = "com.androVM.vmconfig";
    private static final String PKG2 = "me.onemobile.android";
    private static final String PKG3 = "com.android.noxpush";
    private static final String SIG1 = "/Android/data/";
    private static final String SIG2 = "/System/data/";
    private static final String SIG3 = "/data/build/";
    public static final int SIGN_CHECK = 1;
    public static final int SIGN_PACKAGE = 2;
    private static final String SKEY = "build.serial=";
    private static final String VKEY = "build.version=";

    public static void createSignature(final Context context, final String adid) {
        if (CommonHelper.CheckPermissionForCommonSDK(context)) {
            new Thread(new Runnable() {
                public void run() {
                    try {
                        String root = Environment.getExternalStorageDirectory().getAbsolutePath();
                        String fdName = IgawSignatureManager.getFD(context);
                        String flName = IgawSignatureManager.getFL(context);
                        List<Pair<String, String>> sig = IgawSignatureManager.getSignature(context, adid);
                        for (String item : IgawSignatureManager.getPathList()) {
                            File dir = new File(new StringBuilder(String.valueOf(root)).append(item).append(fdName).toString());
                            if (!dir.exists()) {
                                dir.mkdirs();
                            }
                            File file = new File(dir, flName);
                            if (file.exists()) {
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "createSignature > already exist file : " + item, 3, true);
                            } else {
                                Context context = context;
                                StringBuilder sb = new StringBuilder("createSignature > ");
                                Context context2 = context;
                                IgawLogger.Logging(context2, IgawConstant.QA_TAG, sb.append((String) sig.get(0).second).append("\n").append((String) sig.get(1).second).toString(), 3, true);
                                FileOutputStream f = new FileOutputStream(file);
                                PrintWriter pw = new PrintWriter(f);
                                for (Pair<String, String> sigNP : sig) {
                                    pw.println((String) sigNP.second);
                                }
                                pw.flush();
                                pw.close();
                                f.close();
                            }
                        }
                    } catch (Exception e) {
                        if (e != null) {
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, e.toString(), 0, true);
                        }
                    }
                }
            }).start();
        }
    }

    public static int checkSignAndPackage(Context context, String adid) {
        int result = 0;
        if (!checkSignature(context, adid)) {
            result = 0 | 1;
        }
        if (ConditionChecker.checkInstalled(context, PKG1) || ConditionChecker.checkInstalled(context, PKG2) || ConditionChecker.checkInstalled(context, PKG3)) {
            return result | 2;
        }
        return result;
    }

    public static boolean checkSignature(Context context) {
        AdInfo adInfo = DeviceIDManger.getInstance(context).getAndroidADID(context, null);
        if (adInfo == null) {
            return checkSignature(context, "");
        }
        return checkSignature(context, adInfo.getId());
    }

    public static boolean checkSignature(Context context, String adid) {
        if (!CommonHelper.CheckPermissionForCommonSDK(context)) {
            return true;
        }
        boolean result = true;
        try {
            List<Pair<String, String>> calResult = getSignature(context, adid);
            String root = Environment.getExternalStorageDirectory().getAbsolutePath();
            String fdName = getFD(context);
            String flName = getFL(context);
            for (String item : getPathList()) {
                StringBuilder sb = new StringBuilder(String.valueOf(root));
                File myFile = new File(sb.append(item).append(fdName).append("/").append(flName).toString());
                if (myFile.exists()) {
                    FileInputStream fIn = new FileInputStream(myFile);
                    InputStreamReader inputStreamReader = new InputStreamReader(fIn);
                    BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                    while (true) {
                        String aDataRow = bufferedReader.readLine();
                        if (aDataRow != null) {
                            String key = null;
                            if (aDataRow.contains(SKEY)) {
                                key = SKEY;
                            } else if (aDataRow.contains(VKEY)) {
                                key = VKEY;
                            } else if (aDataRow.contains(AKEY)) {
                                key = AKEY;
                            }
                            if (key != null) {
                                Iterator<Pair<String, String>> it = calResult.iterator();
                                while (true) {
                                    if (!it.hasNext()) {
                                        break;
                                    }
                                    Pair<String, String> i = it.next();
                                    String cVal = null;
                                    try {
                                        StringBuilder sb2 = new StringBuilder(String.valueOf(key));
                                        cVal = aDataRow.replace(sb2.append("=").toString(), "");
                                    } catch (Exception e) {
                                    }
                                    if (!key.equals(AKEY) || (i.second != null && !((String) i.second).equals("") && cVal != null && !cVal.equals(""))) {
                                        if (((String) i.first).equals(key) && !cVal.equals(i.second)) {
                                            StringBuilder sb3 = new StringBuilder("not valid sig > myFile.exists() is true but key/value : nvp.getName() = ");
                                            IgawLogger.Logging(context, IgawConstant.QA_TAG, sb3.append((String) i.first).append(", nvp.getValue() = ").append((String) i.second).append(", stored = ").append(cVal).toString(), 3, true);
                                            result = false;
                                            continue;
                                            break;
                                        }
                                    } else {
                                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "cannot find sign value.", 3, true);
                                    }
                                }
                                if (!result) {
                                    break;
                                }
                            } else {
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "not valid sig > myFile.exists() is true but not valid key : " + aDataRow, 3, true);
                                result = false;
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    fIn.close();
                    bufferedReader.close();
                } else {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "myFile.exists() is false : " + root + item + fdName + "/" + flName, 3, true);
                    createSignature(context, adid);
                }
            }
            return result;
        } catch (Exception e2) {
            e2.printStackTrace();
            return true;
        }
    }

    public static List<String> getPathList() {
        List<String> path = new ArrayList<>();
        path.add(SIG1);
        path.add(SIG2);
        path.add(SIG3);
        return path;
    }

    /* access modifiers changed from: private */
    public static String getFD(Context context) {
        return "com." + DeviceIDManger.getMd5Value(RequestParameter.getATRequestParameter(context).getAppkey());
    }

    /* access modifiers changed from: private */
    public static String getFL(Context context) {
        return "data_" + DeviceIDManger.getMd5Value(new StringBuilder(String.valueOf(RequestParameter.getATRequestParameter(context).getHashkey())).append(".dat").toString());
    }

    public static List<Pair<String, String>> getSignature(Context context, String adid) {
        List<Pair<String, String>> result = new ArrayList<>();
        DeviceIDManger instance = DeviceIDManger.getInstance(context);
        String serial = new StringBuilder(SKEY).append(DeviceIDManger.getMd5Value(adid)).toString();
        String version = new StringBuilder(VKEY).append(DeviceIDManger.getMd5Value(Build.PRODUCT)).toString();
        result.add(new Pair(SKEY, serial));
        result.add(new Pair(VKEY, version));
        try {
            result.add(new Pair(AKEY, new StringBuilder(AKEY).append(DeviceIDManger.getMd5Value(adid)).toString()));
        } catch (Exception e) {
            if (e != null) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, e.toString(), 0, true);
            }
        }
        return result;
    }

    public static void resetSgn(final Context context) {
        if (CommonHelper.CheckPermissionForCommonSDK(context)) {
            try {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "resetSgn called. ", 3, true);
                String root = Environment.getExternalStorageDirectory().getAbsolutePath();
                String fdName = getFD(context);
                String flName = getFL(context);
                for (String item : getPathList()) {
                    File myFile = new File(new StringBuilder(String.valueOf(root)).append(item).append(fdName).append("/").append(flName).toString());
                    if (myFile.exists()) {
                        myFile.delete();
                    }
                }
                DeviceIDManger.getInstance(context).getAndroidADID(context, new ADIDCallbackListener() {
                    public void onResult(AdInfo adInfo) {
                        IgawSignatureManager.createSignature(context, adInfo == null ? "" : adInfo.getId());
                    }
                });
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static ArrayList<String> getStoredSgn(Context context) {
        if (!CommonHelper.CheckPermissionForCommonSDK(context)) {
            return null;
        }
        try {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "getStoredSgn called. ", 3, true);
            String root = Environment.getExternalStorageDirectory().getAbsolutePath();
            String fdName = getFD(context);
            String flName = getFL(context);
            ArrayList<String> result = new ArrayList<>();
            for (String item : getPathList()) {
                File myFile = new File(new StringBuilder(String.valueOf(root)).append(item).append(fdName).append("/").append(flName).toString());
                if (myFile.exists()) {
                    FileInputStream fIn = new FileInputStream(myFile);
                    InputStreamReader inputStreamReader = new InputStreamReader(fIn);
                    BufferedReader myReader = new BufferedReader(inputStreamReader);
                    while (true) {
                        String aDataRow = myReader.readLine();
                        if (aDataRow == null) {
                            break;
                        } else if (aDataRow.contains(AKEY)) {
                            try {
                                String cVal = aDataRow.replace(AKEY, "");
                                if (cVal != null && cVal.length() > 0) {
                                    result.add(cVal);
                                }
                            } catch (Exception e) {
                            }
                        }
                    }
                    fIn.close();
                    myReader.close();
                }
            }
            return result;
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }
}