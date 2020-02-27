package com.igaworks.util;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager.NameNotFoundException;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build.VERSION;
import android.util.Log;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.dao.AppImpressionDAO;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.interfaces.CommonInterface;
import com.kakao.util.helper.CommonProtocol;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class CommonHelper {
    public static int REQUEST_CODE_ASK_MULTIPLE_PERMISSIONS = 124;
    private static SSLSocketFactory TRUSTED_FACTORY;
    private static HostnameVerifier TRUSTED_VERIFIER;

    @TargetApi(21)
    public static boolean checkAppInFocus(Context context, String PackageName) throws NameNotFoundException {
        if (VERSION.SDK_INT < 21 || !((ActivityManager) context.getSystemService("activity")).getAppTasks().get(0).getTaskInfo().baseIntent.getComponent().getPackageName().equals(PackageName)) {
            return false;
        }
        return true;
    }

    public static boolean checkInternetConnection(Context context) {
        try {
            if (CommonFrameworkImpl.REMOVE_NETWORKS_STATE_PERMISSION) {
                return true;
            }
            NetworkInfo activeNetwork = ((ConnectivityManager) context.getSystemService("connectivity")).getActiveNetworkInfo();
            if (activeNetwork == null || !activeNetwork.isConnectedOrConnecting()) {
                return false;
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return true;
        }
    }

    public static boolean checkPermission(Context context, String permissionName) {
        try {
            if (context.getPackageManager().checkPermission(permissionName, context.getPackageName()) == 0) {
                return true;
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @TargetApi(23)
    public static boolean checkSelfPermission(Context context, String permissionName) {
        try {
            if (VERSION.SDK_INT < 23) {
                return checkPermission(context, permissionName);
            }
            try {
                if (context.checkSelfPermission(permissionName) == 0) {
                    return true;
                }
                return false;
            } catch (Exception e1) {
                e1.printStackTrace();
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "checkSelfPermission Error: " + e1.getMessage(), 0);
                return false;
            }
        } catch (Exception e2) {
            e2.printStackTrace();
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "checkSelfPermission Error: " + e2.getMessage(), 0);
            return false;
        }
    }

    public static boolean checkReceiver(Context context) {
        try {
            if (context.getPackageManager().getReceiverInfo(new ComponentName(context, "com.igaworks.IgawReceiver"), 128) != null) {
                return true;
            }
            return false;
        } catch (NameNotFoundException e) {
            return false;
        } catch (Exception e2) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "checkReceiver error : " + e2.toString(), 0);
            return false;
        }
    }

    public static String GetKSTCreateAtAsString() {
        SimpleDateFormat sdf = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT, Locale.KOREA);
        sdf.setTimeZone(TimeZone.getTimeZone("GMT+9"));
        return sdf.format(new Date());
    }

    public static String GetKSTServerTimeAsString(Context context) {
        SimpleDateFormat sdf = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT, Locale.KOREA);
        sdf.setTimeZone(TimeZone.getTimeZone("GMT+9"));
        return sdf.format(new Date(System.currentTimeMillis() + AppImpressionDAO.getServerBaseTimeOffset(context)));
    }

    public static String getCurrentKST_DBFormat() {
        SimpleDateFormat sdfKST = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT2, Locale.KOREA);
        sdfKST.setTimeZone(TimeZone.getTimeZone("GMT+9"));
        return sdfKST.format(new Date());
    }

    public static Date getKSTDate_fromDB(String dateStr) {
        try {
            SimpleDateFormat sdfKST = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT2, Locale.KOREA);
            sdfKST.setTimeZone(TimeZone.getTimeZone("GMT+9"));
            return sdfKST.parse(dateStr);
        } catch (ParseException e) {
            e.printStackTrace();
            return null;
        }
    }

    @TargetApi(23)
    public static boolean CheckandRequestPermissionForCommonSDK(Context context) {
        try {
            if (!(context instanceof Activity) || VERSION.SDK_INT < 23) {
                if (!(context instanceof Activity)) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "context is not an activity context.", 3, false);
                }
                boolean canAccessInternet = checkSelfPermission(context, "android.permission.INTERNET");
                boolean canAccessNetworkState = checkSelfPermission(context, "android.permission.ACCESS_NETWORK_STATE");
                boolean canReadExternalStorage = checkSelfPermission(context, "android.permission.READ_EXTERNAL_STORAGE");
                boolean canWriteExternalStrorage = checkSelfPermission(context, "android.permission.WRITE_EXTERNAL_STORAGE");
                if (!canAccessInternet || !canAccessNetworkState || !canReadExternalStorage || !canWriteExternalStrorage) {
                    return false;
                }
                return true;
            }
            final Activity openAct = (Activity) context;
            final List<String> permissionsNeeded = new ArrayList<>();
            final List<String> permissionsList = new ArrayList<>();
            boolean canAccessInternet2 = checkSelfPermission(context, "android.permission.INTERNET");
            if (!canAccessInternet2) {
                permissionsNeeded.add("android.permission.INTERNET");
                if (openAct.shouldShowRequestPermissionRationale("android.permission.INTERNET")) {
                    permissionsList.add("android.permission.INTERNET");
                }
            }
            boolean canAccessNetworkState2 = checkSelfPermission(context, "android.permission.ACCESS_NETWORK_STATE");
            if (!canAccessNetworkState2) {
                permissionsNeeded.add("android.permission.ACCESS_NETWORK_STATE");
                if (openAct.shouldShowRequestPermissionRationale("android.permission.ACCESS_NETWORK_STATE")) {
                    permissionsList.add("android.permission.ACCESS_NETWORK_STATE");
                }
            }
            boolean canReadExternalStorage2 = checkSelfPermission(context, "android.permission.READ_EXTERNAL_STORAGE");
            if (!canReadExternalStorage2) {
                permissionsNeeded.add("android.permission.READ_EXTERNAL_STORAGE");
                if (openAct.shouldShowRequestPermissionRationale("android.permission.READ_EXTERNAL_STORAGE")) {
                    permissionsList.add("android.permission.READ_EXTERNAL_STORAGE");
                }
            }
            boolean canWriteExternalStrorage2 = checkSelfPermission(context, "android.permission.WRITE_EXTERNAL_STORAGE");
            if (!canWriteExternalStrorage2) {
                permissionsNeeded.add("android.permission.WRITE_EXTERNAL_STORAGE");
                if (openAct.shouldShowRequestPermissionRationale("android.permission.WRITE_EXTERNAL_STORAGE")) {
                    permissionsList.add("android.permission.WRITE_EXTERNAL_STORAGE");
                }
            }
            openAct.runOnUiThread(new Runnable() {
                public void run() {
                    if (permissionsList.size() > 0 && permissionsNeeded.size() > 0) {
                        openAct.requestPermissions((String[]) permissionsList.toArray(new String[permissionsList.size()]), CommonHelper.REQUEST_CODE_ASK_MULTIPLE_PERMISSIONS);
                    }
                }
            });
            if (!canAccessInternet2 || !canAccessNetworkState2 || !canReadExternalStorage2 || !canWriteExternalStrorage2) {
                return false;
            }
            return true;
        } catch (Exception e) {
            Log.e(IgawConstant.QA_TAG, "GrantPermissionForCommonSDK Error: " + e.getMessage());
            return false;
        }
    }

    @TargetApi(23)
    public static boolean CheckPermissionForCommonSDK(Context context) {
        try {
            boolean canAccessInternet = checkSelfPermission(context, "android.permission.INTERNET");
            boolean canAccessNetworkState = checkSelfPermission(context, "android.permission.ACCESS_NETWORK_STATE");
            boolean canReadExternalStorage = true;
            if (VERSION.SDK_INT >= 19) {
                canReadExternalStorage = checkSelfPermission(context, "android.permission.READ_EXTERNAL_STORAGE");
            }
            boolean canWriteExternalStrorage = checkSelfPermission(context, "android.permission.WRITE_EXTERNAL_STORAGE");
            if (!canAccessInternet || !canAccessNetworkState || !canReadExternalStorage || !canWriteExternalStrorage) {
                return false;
            }
            return true;
        } catch (Exception e) {
            Log.e(IgawConstant.QA_TAG, "CheckPermissionForCommonSDK Error: " + e.getMessage());
            return false;
        }
    }

    @TargetApi(23)
    public static void RequestPermissionForCommonSDK(Context context) {
        try {
            if ((context instanceof Activity) && VERSION.SDK_INT >= 23) {
                final Activity openAct = (Activity) context;
                final List<String> permissionsNeeded = new ArrayList<>();
                if (!checkSelfPermission(context, "android.permission.INTERNET")) {
                    permissionsNeeded.add("android.permission.INTERNET");
                }
                if (!checkSelfPermission(context, "android.permission.ACCESS_NETWORK_STATE")) {
                    permissionsNeeded.add("android.permission.ACCESS_NETWORK_STATE");
                }
                if (!checkSelfPermission(context, "android.permission.READ_EXTERNAL_STORAGE")) {
                    permissionsNeeded.add("android.permission.READ_EXTERNAL_STORAGE");
                }
                if (!checkSelfPermission(context, "android.permission.WRITE_EXTERNAL_STORAGE")) {
                    permissionsNeeded.add("android.permission.WRITE_EXTERNAL_STORAGE");
                }
                openAct.runOnUiThread(new Runnable() {
                    public void run() {
                        if (permissionsNeeded.size() > 0) {
                            openAct.requestPermissions((String[]) permissionsNeeded.toArray(new String[permissionsNeeded.size()]), CommonHelper.REQUEST_CODE_ASK_MULTIPLE_PERMISSIONS);
                        }
                    }
                });
            } else if (!(context instanceof Activity)) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "context is not an activity context.", 3, false);
            }
        } catch (Exception e) {
            Log.e(IgawConstant.QA_TAG, "RequestPermissionForCommonSDK Error: " + e.getMessage());
        }
    }

    @TargetApi(23)
    public static boolean CheckAndRequestGrantPermissionForLiveOpsSDK(Context context) {
        try {
            if (!(context instanceof Activity) || VERSION.SDK_INT < 23) {
                boolean CD2M_RECEIVE = checkSelfPermission(context, "com.google.android.c2dm.permission.RECEIVE");
                boolean custom = checkSelfPermission(context, context.getPackageName() + ".permission.C2D_MESSAGE");
                if (!CD2M_RECEIVE || !custom) {
                    return false;
                }
                return true;
            }
            final Activity openAct = (Activity) context;
            final List<String> permissionsNeeded = new ArrayList<>();
            final List<String> permissionsList = new ArrayList<>();
            boolean CD2M_RECEIVE2 = checkPermission(context, "com.google.android.c2dm.permission.RECEIVE");
            if (!CD2M_RECEIVE2) {
                permissionsNeeded.add("com.google.android.c2dm.permission.RECEIVE");
                if (openAct.shouldShowRequestPermissionRationale("com.google.android.c2dm.permission.RECEIVE")) {
                    permissionsList.add("com.google.android.c2dm.permission.RECEIVE");
                }
            }
            boolean custom2 = checkPermission(context, context.getPackageName() + ".permission.C2D_MESSAGE");
            if (!custom2) {
                permissionsNeeded.add(context.getPackageName() + ".permission.C2D_MESSAGE");
                if (openAct.shouldShowRequestPermissionRationale(context.getPackageName() + ".permission.C2D_MESSAGE")) {
                    permissionsList.add(context.getPackageName() + ".permission.C2D_MESSAGE");
                }
            }
            openAct.runOnUiThread(new Runnable() {
                public void run() {
                    if (permissionsList.size() > 0 && permissionsNeeded.size() > 0) {
                        openAct.requestPermissions((String[]) permissionsList.toArray(new String[permissionsList.size()]), CommonHelper.REQUEST_CODE_ASK_MULTIPLE_PERMISSIONS);
                    }
                }
            });
            if (!CD2M_RECEIVE2 || !custom2) {
                return false;
            }
            return true;
        } catch (Exception e) {
            Log.e(IgawConstant.QA_TAG, "GrantPermissionForCommonSDK Error: " + e.getMessage());
            return false;
        }
    }

    @TargetApi(23)
    public static boolean CheckPermissionForLiveOpsSDK(Context context) {
        try {
            boolean CD2M_RECEIVE = checkSelfPermission(context, "com.google.android.c2dm.permission.RECEIVE");
            boolean custom = checkSelfPermission(context, context.getPackageName() + ".permission.C2D_MESSAGE");
            if (!CD2M_RECEIVE || !custom) {
                return false;
            }
            return true;
        } catch (Exception e) {
            Log.e(IgawConstant.QA_TAG, "CheckPermissionForLiveOpsSDK Error: " + e.getMessage());
            return false;
        }
    }

    public static Bitmap getBitmapFromURL(String imageUrl) {
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(imageUrl).openConnection();
            connection.setDoInput(true);
            connection.connect();
            return BitmapFactory.decodeStream(connection.getInputStream());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String loadJSONFromS3(String configFileUrl) {
        try {
            URL url = new URL(configFileUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            if (configFileUrl.startsWith(CommonProtocol.URL_SCHEME)) {
                ((HttpsURLConnection) connection).setHostnameVerifier(getTrustedVerifier());
                ((HttpsURLConnection) connection).setSSLSocketFactory(getTrustedFactory());
            }
            connection.setReadTimeout(15000);
            connection.setConnectTimeout(15000);
            connection.setDoInput(true);
            connection.connect();
            InputStream input = new BufferedInputStream(url.openStream());
            StringBuffer responseBuffer = new StringBuffer();
            while (true) {
                byte[] byteArray = new byte[1024];
                if (input.read(byteArray) == -1) {
                    return responseBuffer.toString().trim();
                }
                responseBuffer.append(new String(byteArray, "UTF-8"));
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return null;
        } catch (IOException e2) {
            e2.printStackTrace();
            return null;
        }
    }

    private static HostnameVerifier getTrustedVerifier() {
        if (TRUSTED_VERIFIER == null) {
            TRUSTED_VERIFIER = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };
        }
        return TRUSTED_VERIFIER;
    }

    private static SSLSocketFactory getTrustedFactory() {
        if (TRUSTED_FACTORY == null) {
            TrustManager[] trustAllCerts = {new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    try {
                        chain[0].checkValidity();
                    } catch (Exception e) {
                        throw new CertificateException("Certificate not valid or trusted.");
                    }
                }
            }};
            try {
                SSLContext context = SSLContext.getInstance("TLS");
                context.init(null, trustAllCerts, new SecureRandom());
                TRUSTED_FACTORY = context.getSocketFactory();
            } catch (GeneralSecurityException e) {
                Log.e(IgawConstant.QA_TAG, "CommonHelper > SSL Error: " + e.getMessage());
            }
        }
        return TRUSTED_FACTORY;
    }

    public static boolean findBinary(String binaryName) {
        if (0 != 0) {
            return false;
        }
        String[] places = {"/sbin/", "/system/bin/", "/system/xbin/", "/data/local/xbin/", "/data/local/bin/", "/system/sd/xbin/", "/system/bin/failsafe/", "/data/local/"};
        int length = places.length;
        for (int i = 0; i < length; i++) {
            if (new File(places[i] + binaryName).exists()) {
                return true;
            }
        }
        return false;
    }
}