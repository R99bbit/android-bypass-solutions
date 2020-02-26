package a.b.a.g;

import a.b.a.b.l;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.location.LocationManager;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build.VERSION;
import android.os.SystemClock;
import android.telephony.CellIdentityGsm;
import android.telephony.CellIdentityLte;
import android.telephony.CellIdentityWcdma;
import android.telephony.CellInfo;
import android.telephony.CellInfoCdma;
import android.telephony.CellInfoGsm;
import android.telephony.CellInfoLte;
import android.telephony.CellInfoWcdma;
import android.telephony.CellLocation;
import android.telephony.CellSignalStrengthGsm;
import android.telephony.CellSignalStrengthLte;
import android.telephony.CellSignalStrengthWcdma;
import android.telephony.TelephonyManager;
import android.telephony.gsm.GsmCellLocation;
import android.util.Log;
import androidx.annotation.Nullable;
import co.habitfactory.signalfinance_embrain.comm.ResultCode;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import com.loplat.placeengine.PlaceEngineBase;
import com.loplat.placeengine.cloud.RequestMessage.CellTowerInfo;
import com.loplat.placeengine.cloud.RequestMessage.Connection;
import com.loplat.placeengine.cloud.ResponseMessage.Station;
import com.loplat.placeengine.wifi.WifiType;
import java.lang.reflect.Method;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;

/* compiled from: StatusManager */
public class a {

    /* renamed from: a reason: collision with root package name */
    public static HashMap<String, Station> f41a;
    public static ArrayList<Station> b;
    public static ArrayList<String> c;
    public static String d;

    public static double a(double d2) {
        return (d2 * 3.141592653589793d) / 180.0d;
    }

    public static float a(float f) {
        float f2;
        float f3 = 0.2f;
        if (f > 150.0f) {
            return 0.45f;
        }
        if (f > 50.0f) {
            f2 = ((f - 50.0f) * 0.14999998f) / 100.0f;
            f3 = 0.3f;
        } else if (f <= 20.0f) {
            return 0.2f;
        } else {
            f2 = ((f - 20.0f) * 0.10000001f) / 30.0f;
        }
        return f3 + f2;
    }

    public static void a(int i, String str, String str2) {
        switch (i) {
            case 1:
                Log.v(str, str2);
                return;
            case 2:
                Log.d(str, str2);
                return;
            case 3:
                Log.i(str, str2);
                return;
            case 4:
                Log.w(str, str2);
                return;
            case 5:
                Log.e(str, str2);
                return;
            case 6:
                Log.wtf(str, str2);
                return;
            default:
                return;
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:113:? A[RETURN, SYNTHETIC] */
    /* JADX WARNING: Removed duplicated region for block: B:13:0x0024  */
    /* JADX WARNING: Removed duplicated region for block: B:65:0x0130 A[Catch:{ Error | Exception | SecurityException -> 0x01a4, Error | Exception | SecurityException -> 0x01a4, Error | Exception | SecurityException -> 0x01a4 }] */
    /* JADX WARNING: Removed duplicated region for block: B:67:0x0139 A[Catch:{ Error | Exception | SecurityException -> 0x01a4, Error | Exception | SecurityException -> 0x01a4, Error | Exception | SecurityException -> 0x01a4 }] */
    /* JADX WARNING: Removed duplicated region for block: B:69:0x0142 A[ADDED_TO_REGION, Catch:{ Error | Exception | SecurityException -> 0x01a4, Error | Exception | SecurityException -> 0x01a4, Error | Exception | SecurityException -> 0x01a4 }] */
    /* JADX WARNING: Removed duplicated region for block: B:75:0x0161 A[Catch:{ Error | Exception | SecurityException -> 0x01a4, Error | Exception | SecurityException -> 0x01a4, Error | Exception | SecurityException -> 0x01a4 }] */
    /* JADX WARNING: Removed duplicated region for block: B:93:0x01a9 A[SYNTHETIC, Splitter:B:93:0x01a9] */
    public static CellTowerInfo b(Context context) {
        boolean z;
        CellTowerInfo cellTowerInfo;
        int i;
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        CellTowerInfo cellTowerInfo2;
        String c2;
        ArrayList<Integer> g;
        Context context2 = context;
        try {
            ConnectivityManager connectivityManager = (ConnectivityManager) context2.getSystemService("connectivity");
            if (connectivityManager != null) {
                NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
                if (activeNetworkInfo != null && activeNetworkInfo.getType() == 0 && activeNetworkInfo.isRoaming()) {
                    z = false;
                    if (z) {
                        TelephonyManager telephonyManager = (TelephonyManager) context2.getSystemService("phone");
                        if (telephonyManager != null) {
                            if (VERSION.SDK_INT >= 17) {
                                List<CellInfo> allCellInfo = telephonyManager.getAllCellInfo();
                                if (allCellInfo != null) {
                                    i4 = 0;
                                    int i7 = -1;
                                    i3 = Integer.MAX_VALUE;
                                    int i8 = -1;
                                    i2 = -1;
                                    i = -1;
                                    for (CellInfo next : allCellInfo) {
                                        if (next.isRegistered()) {
                                            if (next instanceof CellInfoGsm) {
                                                CellIdentityGsm cellIdentity = ((CellInfoGsm) next).getCellIdentity();
                                                CellSignalStrengthGsm cellSignalStrength = ((CellInfoGsm) next).getCellSignalStrength();
                                                i7 = cellIdentity.getCid();
                                                i3 = cellSignalStrength.getDbm();
                                                i8 = cellIdentity.getLac();
                                                i = cellIdentity.getMnc();
                                                i2 = cellIdentity.getMcc();
                                                i4 = 3;
                                            } else if (next instanceof CellInfoLte) {
                                                CellIdentityLte cellIdentity2 = ((CellInfoLte) next).getCellIdentity();
                                                CellSignalStrengthLte cellSignalStrength2 = ((CellInfoLte) next).getCellSignalStrength();
                                                i7 = cellIdentity2.getCi();
                                                i8 = cellIdentity2.getTac();
                                                i3 = cellSignalStrength2.getDbm();
                                                i = cellIdentity2.getMnc();
                                                i2 = cellIdentity2.getMcc();
                                                i4 = 1;
                                            } else if (next instanceof CellInfoCdma) {
                                                i4 = 4;
                                            } else if (VERSION.SDK_INT >= 18 && (next instanceof CellInfoWcdma)) {
                                                CellIdentityWcdma cellIdentity3 = ((CellInfoWcdma) next).getCellIdentity();
                                                CellSignalStrengthWcdma cellSignalStrength3 = ((CellInfoWcdma) next).getCellSignalStrength();
                                                i7 = cellIdentity3.getCid();
                                                i3 = cellSignalStrength3.getDbm();
                                                i8 = cellIdentity3.getLac();
                                                i = cellIdentity3.getMnc();
                                                i2 = cellIdentity3.getMcc();
                                                i4 = 2;
                                            }
                                        }
                                    }
                                    i5 = i7;
                                    i6 = i8;
                                    if ((i4 == 1 || i4 == 2 || i4 == 3) && i5 >= 0 && i5 < Integer.MAX_VALUE) {
                                        cellTowerInfo2 = new CellTowerInfo();
                                        cellTowerInfo2.setCellType(i4);
                                        cellTowerInfo2.setCellId(Integer.valueOf(i5));
                                        if (i3 < Integer.MAX_VALUE) {
                                            cellTowerInfo2.setDbm(Integer.valueOf(i3));
                                        }
                                        if (i6 < Integer.MAX_VALUE) {
                                            cellTowerInfo2.setLac(Integer.valueOf(i6));
                                        }
                                        if (i2 > -1 || i2 >= Integer.MAX_VALUE || i <= -1 || i >= Integer.MAX_VALUE) {
                                            g = g(context);
                                            if (g.size() > 1) {
                                                int intValue = g.get(0).intValue();
                                                int intValue2 = g.get(1).intValue();
                                                if (intValue > -1 && intValue < Integer.MAX_VALUE) {
                                                    cellTowerInfo2.setMnc(Integer.valueOf(intValue));
                                                }
                                                if (intValue2 > -1 && intValue2 < Integer.MAX_VALUE) {
                                                    cellTowerInfo2.setMcc(Integer.valueOf(intValue2));
                                                }
                                            }
                                        } else {
                                            cellTowerInfo2.setMcc(Integer.valueOf(i2));
                                            cellTowerInfo2.setMnc(Integer.valueOf(i));
                                        }
                                        c2 = c(context);
                                        if (c2 != null && !c2.isEmpty()) {
                                            cellTowerInfo2.setIp(c2);
                                        }
                                        cellTowerInfo2.setTime(SystemClock.elapsedRealtime());
                                        cellTowerInfo = cellTowerInfo2;
                                        if (cellTowerInfo == null) {
                                            return cellTowerInfo;
                                        }
                                        try {
                                            if (!(cellTowerInfo.getMcc() == null || cellTowerInfo.getMnc() == null)) {
                                                return cellTowerInfo;
                                            }
                                            return null;
                                        } catch (Error | Exception | SecurityException unused) {
                                            return cellTowerInfo;
                                        }
                                    }
                                }
                            } else {
                                CellLocation cellLocation = telephonyManager.getCellLocation();
                                if (cellLocation != null && (cellLocation instanceof GsmCellLocation)) {
                                    GsmCellLocation gsmCellLocation = (GsmCellLocation) telephonyManager.getCellLocation();
                                    i5 = gsmCellLocation.getCid() > -1 ? gsmCellLocation.getCid() : -1;
                                    i6 = gsmCellLocation.getLac() > -1 ? gsmCellLocation.getLac() : -1;
                                    i4 = 3;
                                    i3 = Integer.MAX_VALUE;
                                    i2 = -1;
                                    i = -1;
                                    cellTowerInfo2 = new CellTowerInfo();
                                    cellTowerInfo2.setCellType(i4);
                                    cellTowerInfo2.setCellId(Integer.valueOf(i5));
                                    if (i3 < Integer.MAX_VALUE) {
                                    }
                                    if (i6 < Integer.MAX_VALUE) {
                                    }
                                    if (i2 > -1) {
                                    }
                                    g = g(context);
                                    if (g.size() > 1) {
                                    }
                                    c2 = c(context);
                                    cellTowerInfo2.setIp(c2);
                                    cellTowerInfo2.setTime(SystemClock.elapsedRealtime());
                                    cellTowerInfo = cellTowerInfo2;
                                    if (cellTowerInfo == null) {
                                    }
                                }
                            }
                            i6 = -1;
                            i5 = -1;
                            i4 = 0;
                            i3 = Integer.MAX_VALUE;
                            i2 = -1;
                            i = -1;
                            cellTowerInfo2 = new CellTowerInfo();
                            try {
                                cellTowerInfo2.setCellType(i4);
                                cellTowerInfo2.setCellId(Integer.valueOf(i5));
                                if (i3 < Integer.MAX_VALUE) {
                                }
                                if (i6 < Integer.MAX_VALUE) {
                                }
                                if (i2 > -1) {
                                }
                                g = g(context);
                                if (g.size() > 1) {
                                }
                                c2 = c(context);
                                cellTowerInfo2.setIp(c2);
                                cellTowerInfo2.setTime(SystemClock.elapsedRealtime());
                                cellTowerInfo = cellTowerInfo2;
                                if (cellTowerInfo == null) {
                                }
                            } catch (Error | Exception | SecurityException unused2) {
                                return cellTowerInfo2;
                            }
                        }
                    }
                    cellTowerInfo = null;
                    if (cellTowerInfo == null) {
                    }
                }
            }
            z = true;
            if (z) {
            }
            cellTowerInfo = null;
            if (cellTowerInfo == null) {
            }
        } catch (Error | Exception | SecurityException unused3) {
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:12:0x0024 A[Catch:{ Error | Exception -> 0x00dd }] */
    /* JADX WARNING: Removed duplicated region for block: B:29:0x0048 A[SYNTHETIC, Splitter:B:29:0x0048] */
    /* JADX WARNING: Removed duplicated region for block: B:37:0x0059 A[SYNTHETIC, Splitter:B:37:0x0059] */
    /* JADX WARNING: Removed duplicated region for block: B:82:0x0056 A[SYNTHETIC] */
    public static String c(Context context) {
        String str;
        boolean z;
        String str2;
        boolean z2;
        try {
            ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService("connectivity");
            if (connectivityManager != null) {
                NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
                if (activeNetworkInfo != null && activeNetworkInfo.getType() == 0) {
                    z = true;
                    if (VERSION.SDK_INT < 21) {
                        Network[] allNetworks = connectivityManager.getAllNetworks();
                        int length = allNetworks.length;
                        str = null;
                        int i = 0;
                        while (i < length) {
                            try {
                                Network network = allNetworks[i];
                                if (z) {
                                    try {
                                        if (VERSION.SDK_INT >= 21) {
                                            NetworkCapabilities networkCapabilities = connectivityManager.getNetworkCapabilities(network);
                                            if (networkCapabilities != null && networkCapabilities.hasCapability(12)) {
                                                z2 = true;
                                                if (!z2) {
                                                    str2 = a(context, network);
                                                    if (str2 != null) {
                                                    }
                                                }
                                                i++;
                                            }
                                        }
                                    } catch (Error | Exception unused) {
                                    }
                                    z2 = false;
                                    if (!z2) {
                                    }
                                    i++;
                                } else {
                                    str2 = a(context, network);
                                    if (str2 == null) {
                                        i++;
                                    }
                                }
                                str = str2;
                                i++;
                            } catch (Error | Exception unused2) {
                            }
                        }
                    } else {
                        Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
                        String str3 = null;
                        while (networkInterfaces.hasMoreElements()) {
                            try {
                                NetworkInterface nextElement = networkInterfaces.nextElement();
                                if (!nextElement.getName().contains("wlan")) {
                                    Enumeration<InetAddress> inetAddresses = nextElement.getInetAddresses();
                                    InetAddress inetAddress = null;
                                    InetAddress inetAddress2 = null;
                                    while (inetAddresses.hasMoreElements()) {
                                        InetAddress nextElement2 = inetAddresses.nextElement();
                                        if (nextElement2 != null && !nextElement2.isLoopbackAddress()) {
                                            if (nextElement2 instanceof Inet6Address) {
                                                String[] split = nextElement2.getHostAddress().split("%");
                                                StringBuilder sb = new StringBuilder();
                                                sb.append("check ip v6 address [");
                                                sb.append(split[0]);
                                                sb.append("]");
                                                sb.toString();
                                                inetAddress2 = nextElement2;
                                            } else if (nextElement2 instanceof Inet4Address) {
                                                inetAddress = nextElement2;
                                            }
                                        }
                                    }
                                    if (inetAddress != null) {
                                        str3 = inetAddress.getHostAddress();
                                    } else if (inetAddress2 != null) {
                                        String hostAddress = inetAddress2.getHostAddress();
                                        str3 = hostAddress.contains("%") ? inetAddress2.getHostAddress().split("%")[0] : hostAddress;
                                    }
                                }
                            } catch (Error | Exception unused3) {
                            }
                        }
                        str = str3;
                    }
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("ip address [");
                    sb2.append(str);
                    sb2.append("]");
                    sb2.toString();
                    return str;
                }
            }
            z = false;
            if (VERSION.SDK_INT < 21) {
            }
        } catch (Error | Exception unused4) {
            str = null;
        }
        StringBuilder sb22 = new StringBuilder();
        sb22.append("ip address [");
        sb22.append(str);
        sb22.append("]");
        sb22.toString();
        return str;
    }

    public static String d(Context context) {
        try {
            return context.getSharedPreferences("lhtibaq5ot47p0xrinly", 0).getString("46", null);
        } catch (Exception unused) {
            return null;
        }
    }

    @Nullable
    public static WifiType e(Context context) {
        try {
            NetworkInfo activeNetworkInfo = ((ConnectivityManager) context.getSystemService("connectivity")).getActiveNetworkInfo();
            if (activeNetworkInfo != null && activeNetworkInfo.isConnected() && activeNetworkInfo.getType() == 1) {
                WifiInfo connectionInfo = ((WifiManager) context.getSystemService("wifi")).getConnectionInfo();
                if (connectionInfo != null) {
                    String bssid = connectionInfo.getBSSID();
                    int i = 0;
                    if (VERSION.SDK_INT >= 21) {
                        i = connectionInfo.getFrequency();
                    }
                    int rssi = connectionInfo.getRssi();
                    String ssid = connectionInfo.getSSID();
                    if (ssid == null) {
                        ssid = "";
                    } else if (ssid.startsWith("\"") && connectionInfo.getSSID().endsWith("\"")) {
                        ssid = connectionInfo.getSSID().substring(1, connectionInfo.getSSID().length() - 1);
                    }
                    return new WifiType(bssid, ssid, rssi, i);
                }
            }
        } catch (Exception unused) {
        }
        return null;
    }

    public static Connection f(Context context) {
        Connection connection = new Connection();
        try {
            ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService("connectivity");
            if (connectivityManager != null) {
                NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
                if (activeNetworkInfo != null && activeNetworkInfo.isConnected() && activeNetworkInfo.getType() == 1) {
                    WifiManager wifiManager = (WifiManager) context.getSystemService("wifi");
                    if (wifiManager != null) {
                        WifiInfo connectionInfo = wifiManager.getConnectionInfo();
                        if (connectionInfo != null) {
                            String bssid = connectionInfo.getBSSID();
                            String ssid = connectionInfo.getSSID();
                            if (ssid == null) {
                                ssid = "";
                            } else if (ssid.startsWith("\"") && connectionInfo.getSSID().endsWith("\"")) {
                                ssid = connectionInfo.getSSID().substring(1, connectionInfo.getSSID().length() - 1);
                            }
                            int i = 0;
                            if (VERSION.SDK_INT >= 21) {
                                i = connectionInfo.getFrequency();
                            }
                            int rssi = connectionInfo.getRssi();
                            connection.setNetwork("wifi");
                            connection.setBssid(bssid);
                            connection.setSsid(ssid);
                            connection.setRss(rssi);
                            if (i > 0) {
                                connection.setFrequency(i);
                            }
                        }
                    }
                }
            }
        } catch (Exception unused) {
        }
        return connection;
    }

    public static ArrayList<Integer> g(Context context) {
        ArrayList<Integer> arrayList = new ArrayList<>();
        try {
            TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
            if (telephonyManager != null) {
                String networkOperator = telephonyManager.getNetworkOperator();
                if (networkOperator != null && networkOperator.length() > 0) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("Operator: ");
                    sb.append(networkOperator);
                    sb.toString();
                    int parseInt = Integer.parseInt(networkOperator.substring(0, 3));
                    int parseInt2 = Integer.parseInt(networkOperator.substring(3));
                    arrayList.add(Integer.valueOf(parseInt));
                    arrayList.add(Integer.valueOf(parseInt2));
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("MCC: ");
                    sb2.append(parseInt);
                    sb2.append(", MNC: ");
                    sb2.append(parseInt2);
                    sb2.toString();
                }
            }
        } catch (RuntimeException | SecurityException unused) {
        }
        return arrayList;
    }

    public static int h(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "45", 0) > 0 ? 1 : 0;
    }

    public static int i(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) ResultCode.CODE_40, (int) SignalLibConsts.REBOOT_DELAY_TIMER);
    }

    public static int j(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "41", 240000);
    }

    public static int k(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "42", (int) SignalLibConsts.REBOOT_DELAY_TIMER);
    }

    public static int l(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "42", (int) SignalLibConsts.REBOOT_DELAY_TIMER) * 2;
    }

    public static int m(Context context) {
        int i = 0;
        try {
            return context.getPackageManager().getPackageInfo(context.getPackageName(), i).applicationInfo.targetSdkVersion;
        } catch (NameNotFoundException unused) {
            return i;
        }
    }

    public static boolean n(Context context) {
        NetworkInfo activeNetworkInfo = ((ConnectivityManager) context.getSystemService("connectivity")).getActiveNetworkInfo();
        return activeNetworkInfo != null && activeNetworkInfo.isConnected();
    }

    public static boolean o(Context context) {
        return "ssubway".equals(l.k);
    }

    public static boolean p(Context context) {
        int i = 0;
        try {
            ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService("connectivity");
            if (connectivityManager == null) {
                return false;
            }
            if (VERSION.SDK_INT < 23) {
                NetworkInfo networkInfo = connectivityManager.getNetworkInfo(17);
                if (networkInfo == null) {
                    return false;
                }
                if (networkInfo.isConnected() || networkInfo.isConnectedOrConnecting()) {
                    return true;
                }
                return false;
            }
            Network[] allNetworks = connectivityManager.getAllNetworks();
            int length = allNetworks.length;
            boolean z = false;
            while (i < length) {
                try {
                    NetworkInfo networkInfo2 = connectivityManager.getNetworkInfo(allNetworks[i]);
                    if (networkInfo2.getType() == 17 && (networkInfo2.isConnected() || networkInfo2.isConnectedOrConnecting())) {
                        z = true;
                    }
                    i++;
                } catch (Error | Exception unused) {
                }
            }
            return z;
        } catch (Error | Exception unused2) {
            return false;
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:18:0x0044  */
    /* JADX WARNING: Removed duplicated region for block: B:29:0x0064  */
    /* JADX WARNING: Removed duplicated region for block: B:30:0x0066  */
    /* JADX WARNING: Removed duplicated region for block: B:33:0x0071  */
    /* JADX WARNING: Removed duplicated region for block: B:34:0x0073  */
    public static boolean q(Context context) {
        boolean z;
        boolean z2;
        PackageManager packageManager;
        int i;
        boolean z3 = true;
        if (VERSION.SDK_INT < 23) {
            return true;
        }
        LocationManager locationManager = (LocationManager) context.getSystemService("location");
        if (locationManager != null) {
            try {
                z = locationManager.isProviderEnabled("network");
                try {
                    z2 = locationManager.isProviderEnabled("gps");
                } catch (Exception unused) {
                    z2 = false;
                    StringBuilder sb = new StringBuilder();
                    sb.append(" - isGPSEnable: ");
                    sb.append(z2);
                    sb.append(", isNetworkProviderEnabled: ");
                    sb.append(z);
                    sb.toString();
                    packageManager = context.getPackageManager();
                    int i2 = -1;
                    if (packageManager != null) {
                    }
                    i = -1;
                    StringBuilder a2 = a.a.a.a.a.a(" - ACCESS_FINE_LOCATION: ");
                    a2.append(i != 0);
                    a2.append(", ACCESS_COARSE_LOCATION: ");
                    a2.append(i2 != 0);
                    a2.toString();
                    z3 = false;
                    return z3;
                }
            } catch (Exception unused2) {
                z = false;
                z2 = false;
                StringBuilder sb2 = new StringBuilder();
                sb2.append(" - isGPSEnable: ");
                sb2.append(z2);
                sb2.append(", isNetworkProviderEnabled: ");
                sb2.append(z);
                sb2.toString();
                packageManager = context.getPackageManager();
                int i22 = -1;
                if (packageManager != null) {
                }
                i = -1;
                StringBuilder a22 = a.a.a.a.a.a(" - ACCESS_FINE_LOCATION: ");
                a22.append(i != 0);
                a22.append(", ACCESS_COARSE_LOCATION: ");
                a22.append(i22 != 0);
                a22.toString();
                z3 = false;
                return z3;
            }
        } else {
            z2 = false;
            z = false;
        }
        StringBuilder sb22 = new StringBuilder();
        sb22.append(" - isGPSEnable: ");
        sb22.append(z2);
        sb22.append(", isNetworkProviderEnabled: ");
        sb22.append(z);
        sb22.toString();
        packageManager = context.getPackageManager();
        int i222 = -1;
        if (packageManager != null) {
            try {
                i = packageManager.checkPermission("android.permission.ACCESS_FINE_LOCATION", context.getPackageName());
                try {
                    i222 = packageManager.checkPermission("android.permission.ACCESS_COARSE_LOCATION", context.getPackageName());
                } catch (Exception unused3) {
                }
            } catch (Exception unused4) {
            }
            StringBuilder a222 = a.a.a.a.a.a(" - ACCESS_FINE_LOCATION: ");
            a222.append(i != 0);
            a222.append(", ACCESS_COARSE_LOCATION: ");
            a222.append(i222 != 0);
            a222.toString();
            if ((!z && !z2) || !(i == 0 || i222 == 0)) {
                z3 = false;
            }
            return z3;
        }
        i = -1;
        StringBuilder a2222 = a.a.a.a.a.a(" - ACCESS_FINE_LOCATION: ");
        a2222.append(i != 0);
        a2222.append(", ACCESS_COARSE_LOCATION: ");
        a2222.append(i222 != 0);
        a2222.toString();
        z3 = false;
        return z3;
    }

    public static boolean r(Context context) {
        WifiManager wifiManager = (WifiManager) context.getSystemService("wifi");
        try {
            Method declaredMethod = wifiManager.getClass().getDeclaredMethod("isWifiApEnabled", new Class[0]);
            declaredMethod.setAccessible(true);
            return ((Boolean) declaredMethod.invoke(wifiManager, new Object[0])).booleanValue();
        } catch (Exception unused) {
            return false;
        }
    }

    public static boolean s(Context context) {
        boolean z;
        boolean z2;
        try {
            WifiManager wifiManager = (WifiManager) context.getSystemService("wifi");
            if (wifiManager != null) {
                z2 = wifiManager.isWifiEnabled();
                try {
                    if (VERSION.SDK_INT >= 18) {
                        z = wifiManager.isScanAlwaysAvailable();
                    }
                } catch (Exception unused) {
                }
                z = false;
            } else {
                z = false;
                z2 = false;
            }
        } catch (Exception unused2) {
            z2 = false;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("WiFiScanAvailable: ");
        sb.append(z2);
        sb.append(", ");
        sb.append(z);
        sb.toString();
        if (z2 || z) {
            return true;
        }
        return false;
    }

    public static float a(List<WifiType> list) {
        if (list == null || list.isEmpty()) {
            return 0.0f;
        }
        float f = 0.0f;
        for (WifiType wifiType : list) {
            int i = wifiType.level;
            if (i > -91) {
                int i2 = i + 91;
                f += (float) (i2 * i2);
            }
        }
        return f > 0.0f ? (float) Math.sqrt((double) f) : f;
    }

    public static boolean a(Context context, int i) {
        if (i <= 0) {
            i = 0;
        } else if (i > 24) {
            i = 24;
        }
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "47", i, true);
    }

    public static void a(Context context, String str) {
        a.b.a.c.a.b(context, "lhtibaq5ot47p0xrinly", "46", str, true);
    }

    public static boolean a(Context context, int i, boolean z) {
        if ((z || (!z && PlaceEngineBase.isManualApiCallEnabled(context))) && (i == 0 || i == 1)) {
            return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "45", i, true);
        }
        return false;
    }

    public static String a(Context context) {
        String packageName = context.getPackageName();
        StringBuilder sb = new StringBuilder();
        sb.append("Package Name: ");
        sb.append(packageName);
        sb.toString();
        return packageName;
    }

    public static String a(Context context, Network network) {
        String str = null;
        try {
            if (VERSION.SDK_INT >= 21) {
                LinkProperties linkProperties = ((ConnectivityManager) context.getSystemService("connectivity")).getLinkProperties(network);
                if (linkProperties != null) {
                    for (LinkAddress next : linkProperties.getLinkAddresses()) {
                        InetAddress address = next.getAddress();
                        if (address != null && !address.isLoopbackAddress() && !a(context, address)) {
                            String[] split = next.toString().split("/");
                            if (split.length >= 1) {
                                str = split[0];
                            }
                        }
                    }
                }
            }
        } catch (Error | Exception unused) {
        }
        return str;
    }

    public static boolean a(Context context, InetAddress inetAddress) {
        try {
            ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService("connectivity");
            if (connectivityManager != null) {
                NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
                if (activeNetworkInfo != null && activeNetworkInfo.getType() == 1) {
                    Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
                    while (networkInterfaces.hasMoreElements()) {
                        NetworkInterface nextElement = networkInterfaces.nextElement();
                        Enumeration<InetAddress> inetAddresses = nextElement.getInetAddresses();
                        while (true) {
                            if (inetAddresses.hasMoreElements()) {
                                InetAddress nextElement2 = inetAddresses.nextElement();
                                if (nextElement.getName().contains("wlan") && nextElement2.equals(inetAddress)) {
                                    StringBuilder sb = new StringBuilder();
                                    sb.append("ip address[");
                                    sb.append(inetAddress.getHostAddress());
                                    sb.append("] is the same as wifi ip address[");
                                    sb.append(nextElement2.getHostAddress());
                                    sb.append("]");
                                    sb.toString();
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        } catch (Error | Exception unused) {
        }
        return false;
    }
}