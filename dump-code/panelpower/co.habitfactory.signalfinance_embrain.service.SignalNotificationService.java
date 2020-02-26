package co.habitfactory.signalfinance_embrain.service;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.Intent;
import android.database.SQLException;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.IBinder;
import android.os.PowerManager;
import android.provider.Telephony.Sms;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import android.util.Log;
import androidx.core.app.NotificationCompat;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalLibPrefs;
import co.habitfactory.signalfinance_embrain.comm.SignalUtil;
import co.habitfactory.signalfinance_embrain.dataset.PushDataSet;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperFinanceInfo;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperMissedNotification;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperMissedPushSms;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperSmsReceiveNumber;
import co.habitfactory.signalfinance_embrain.jobservice.JPushPopupService;
import co.habitfactory.signalfinance_embrain.jobservice.JPushSmsPopupService;
import co.habitfactory.signalfinance_embrain.retroapi_url.ResponseResultUrl;
import co.habitfactory.signalfinance_embrain.retroapi_url.response.ComparePushDs;
import co.habitfactory.signalfinance_embrain.retroapi_url.response.PushContentArrayDs;
import co.habitfactory.signalfinance_embrain.retroapi_url.response.PushContentDs;
import co.habitfactory.signalfinance_embrain.retroapi_url.response.PushPatternContentDs;
import com.google.gson.GsonBuilder;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.regex.Pattern;

@TargetApi(18)
public class SignalNotificationService extends NotificationListenerService implements SignalLibConsts {
    static final String FILTER_EQUALS_RULE26 = "scan";
    static final String FILTER_EQUALS_RULE27 = "gps";
    private final String TAG = SignalNotificationService.class.getSimpleName();
    private boolean isConnected;
    private boolean isDefaultSms = false;
    private final long mBlockSec = 10;
    private SignalLibPrefs mPrefs;
    private final String[] selectionArg = {"010", "011", "016", "017", "018", "019", "8210", "+8210", "006", "007", "008", "009", "050"};
    private boolean shouldSendOnConnect;

    public void onCreate() {
    }

    public void onListenerConnected() {
    }

    public void onNotificationRemoved(StatusBarNotification statusBarNotification) {
    }

    public int onStartCommand(Intent intent, int i, int i2) {
        return 1;
    }

    public void onListenerDisconnected() {
        super.onListenerDisconnected();
    }

    public IBinder onBind(Intent intent) {
        return super.onBind(intent);
    }

    /* JADX WARNING: Removed duplicated region for block: B:190:0x02d5 A[Catch:{ Exception -> 0x02e6 }] */
    /* JADX WARNING: Removed duplicated region for block: B:217:0x0315  */
    /* JADX WARNING: Removed duplicated region for block: B:267:0x02ea A[EDGE_INSN: B:267:0x02ea->B:196:0x02ea ?: BREAK  
    EDGE_INSN: B:267:0x02ea->B:196:0x02ea ?: BREAK  , SYNTHETIC] */
    @TargetApi(21)
    public void onNotificationPosted(StatusBarNotification statusBarNotification) {
        String str;
        String str2;
        boolean z;
        String str3;
        String str4;
        boolean z2;
        String[] strArr;
        String[] strArr2;
        boolean z3;
        int length;
        int i;
        boolean z4;
        String[] strArr3;
        String str5;
        boolean z5;
        this.mPrefs = new SignalLibPrefs(this);
        if (this.mPrefs.getBoolean(SignalLibConsts.PREF_STOP_COLLECT, Boolean.valueOf(true)).booleanValue()) {
            Log.d("\uc218\uc9d1\uc815\uc9c0", " : \ud478\uc2dc\ub370\uc774\ud130 \uc218\uc9d1 \uc548\ud568.");
        } else {
            try {
                str = SignalUtil.NULL_TO_STRING(statusBarNotification.getPackageName().toUpperCase());
            } catch (Exception e) {
                e.printStackTrace();
                str = "";
            }
            if (str == null || str.length() <= 0) {
                stopSelf();
                return;
            }
            Bundle bundle = statusBarNotification.getNotification().extras;
            try {
                String NULL_TO_STRING = SignalUtil.NULL_TO_STRING(String.valueOf(statusBarNotification.getPostTime()));
                if (NULL_TO_STRING.length() <= 0) {
                    NULL_TO_STRING = SignalUtil.getCurrentTime("yyyyMMddHHmmssSSS");
                }
                str2 = NULL_TO_STRING;
            } catch (Exception e2) {
                str2 = SignalUtil.getCurrentTime("yyyyMMddHHmmssSSS");
                e2.printStackTrace();
            }
            try {
                if (str.toUpperCase().equals("COM.KAKAO.TALK")) {
                    stopSelf();
                    return;
                } else if (str.toUpperCase().equals("COM.ANDROID.SYSTEMUI")) {
                    stopSelf();
                    return;
                } else if (str.toUpperCase().equals("COM.ESTSOFT.ALYAC")) {
                    stopSelf();
                    return;
                } else if (str.toUpperCase().equals("COM.AHNLAB.V3MOBILEPLUS")) {
                    stopSelf();
                    return;
                } else {
                    try {
                        if (getPackageName().toUpperCase().equals(str)) {
                            stopSelf();
                            return;
                        }
                        String valueOf = String.valueOf(bundle.getCharSequence(NotificationCompat.EXTRA_TITLE));
                        String valueOf2 = String.valueOf(bundle.getCharSequence(NotificationCompat.EXTRA_TEXT));
                        String valueOf3 = String.valueOf(bundle.getCharSequence(NotificationCompat.EXTRA_SUB_TEXT));
                        String valueOf4 = String.valueOf(bundle.getCharSequence(NotificationCompat.EXTRA_BIG_TEXT));
                        if (str.toUpperCase().equals("VIVA.REPUBLICA.TOSS")) {
                            try {
                                if ((valueOf.length() == 0 || "null".equals(valueOf)) && valueOf2.matches("([0-9]{1,3}(?:,?[0-9]{3})*)")) {
                                    return;
                                }
                            } catch (Exception e3) {
                                e3.printStackTrace();
                                return;
                            }
                        }
                        if (!"null".equals(valueOf) || !"null".equals(valueOf2)) {
                            try {
                                int length2 = valueOf.length();
                                try {
                                    if (FILTER_EQUALS_RULE26.equals(valueOf) || FILTER_EQUALS_RULE27.equals(valueOf)) {
                                        stopSelf();
                                        return;
                                    }
                                } catch (Exception e4) {
                                    e4.printStackTrace();
                                }
                                if (valueOf2.length() + length2 <= 5) {
                                    stopSelf();
                                    return;
                                }
                            } catch (Exception e5) {
                                e5.printStackTrace();
                            }
                            if (!checkClientExceptionRule(str, valueOf, valueOf2, valueOf4)) {
                                if (str.toUpperCase().equals("COM.BRINICLEMOBILE.WIBEETALK") && !valueOf2.startsWith("[\uc6b0\ub9ac\uc740\ud589]")) {
                                    stopSelf();
                                    return;
                                } else if (!"COM.SAMSUNG.ANDROID.SPAY".equals(str.toUpperCase()) || (!valueOf2.startsWith("\uc11c\ube44\uc2a4\uac00 \uc2e4\ud589\uc911\uc785\ub2c8\ub2e4.") && !valueOf2.startsWith("Samsung Pay \ubcf4\ud638 \uc911\uc785\ub2c8\ub2e4"))) {
                                    try {
                                        if (VERSION.SDK_INT >= 19) {
                                            try {
                                                str5 = SignalUtil.NULL_TO_STRING(Sms.getDefaultSmsPackage(this));
                                            } catch (Exception e6) {
                                                e6.printStackTrace();
                                                str5 = "";
                                            }
                                            try {
                                                z5 = str5.toUpperCase().equals(str);
                                            } catch (Exception e7) {
                                                e7.printStackTrace();
                                                z5 = false;
                                            }
                                            if (z5) {
                                                long postTime = statusBarNotification.getPostTime();
                                                StringBuilder sb = new StringBuilder();
                                                sb.append(str);
                                                sb.append("|");
                                                sb.append(valueOf);
                                                sb.append("|");
                                                sb.append(valueOf2);
                                                sb.append("|");
                                                sb.append(valueOf3);
                                                String sb2 = sb.toString();
                                                long j = this.mPrefs.getLong(SignalLibConsts.PREF_API_PREF_BEFORE_SBN_TIMESTAMP);
                                                this.mPrefs.putLong(SignalLibConsts.PREF_API_PREF_BEFORE_SBN_TIMESTAMP, postTime);
                                                if (j == -1 || ((postTime - j) / 1000) % 60 >= 10 || !SignalUtil.NULL_TO_STRING(this.mPrefs.getString(SignalLibConsts.PREF_API_PREF_BEFORE_SBN_SUM)).equals(sb2)) {
                                                    this.mPrefs.putString(SignalLibConsts.PREF_API_PREF_BEFORE_SBN_SUM, sb2);
                                                } else {
                                                    return;
                                                }
                                            }
                                        }
                                    } catch (Exception e8) {
                                        e8.printStackTrace();
                                    }
                                    DatabaseHelperFinanceInfo instance = DatabaseHelperFinanceInfo.getInstance(getApplicationContext());
                                    try {
                                        instance.onCreateWithTable(instance.getDB(), DatabaseHelperFinanceInfo.TABLE_NAME);
                                    } catch (Exception e9) {
                                        e9.printStackTrace();
                                    }
                                    if (VERSION.SDK_INT >= 19) {
                                        try {
                                            str4 = SignalUtil.NULL_TO_STRING(Sms.getDefaultSmsPackage(this));
                                        } catch (Exception e10) {
                                            e10.printStackTrace();
                                            str4 = "";
                                        }
                                        try {
                                            z2 = str4.toUpperCase().equals(str);
                                        } catch (Exception e11) {
                                            e11.printStackTrace();
                                            z2 = false;
                                        }
                                        if (z2) {
                                            try {
                                                str3 = valueOf.replaceAll("[^0-9]", "");
                                                if (isPrivateNumber(this.selectionArg, str3)) {
                                                    stopSelf();
                                                    return;
                                                }
                                                this.isDefaultSms = true;
                                                DatabaseHelperSmsReceiveNumber instance2 = DatabaseHelperSmsReceiveNumber.getInstance(getApplicationContext());
                                                String[] strArr4 = null;
                                                try {
                                                    strArr = instance2.getNumber("P");
                                                } catch (SQLException e12) {
                                                    e12.printStackTrace();
                                                    strArr = null;
                                                }
                                                try {
                                                    strArr2 = instance2.getNumber("C");
                                                } catch (Exception e13) {
                                                    e13.printStackTrace();
                                                    strArr2 = null;
                                                }
                                                if (strArr == null || strArr2 == null) {
                                                    try {
                                                        SignalUtil.getAssetData(1, this);
                                                    } catch (Exception e14) {
                                                        e14.printStackTrace();
                                                    }
                                                    try {
                                                        strArr3 = instance2.getNumber("P");
                                                    } catch (SQLException e15) {
                                                        e15.printStackTrace();
                                                        strArr3 = null;
                                                    }
                                                    try {
                                                        strArr2 = instance2.getNumber("C");
                                                        strArr4 = strArr3;
                                                    } catch (SQLException e16) {
                                                        e16.printStackTrace();
                                                    }
                                                } else {
                                                    strArr4 = strArr;
                                                }
                                                if (strArr2 != null) {
                                                    try {
                                                        int length3 = strArr2.length;
                                                        int i2 = 0;
                                                        while (true) {
                                                            if (i2 >= length3) {
                                                                z4 = false;
                                                                break;
                                                            } else if (str3.equalsIgnoreCase(strArr2[i2].trim())) {
                                                                z4 = true;
                                                                break;
                                                            } else {
                                                                i2++;
                                                            }
                                                        }
                                                        z3 = z4;
                                                    } catch (Exception e17) {
                                                        e17.printStackTrace();
                                                    }
                                                    if (!z3 && strArr4 != null) {
                                                        length = strArr4.length;
                                                        i = 0;
                                                        while (true) {
                                                            if (i >= length) {
                                                                break;
                                                            } else if (str3.equalsIgnoreCase(strArr4[i].trim())) {
                                                                z3 = true;
                                                                break;
                                                            } else {
                                                                i++;
                                                            }
                                                        }
                                                    }
                                                    z = z3;
                                                    if (z) {
                                                        PowerManager powerManager = (PowerManager) getSystemService("power");
                                                        if (VERSION.SDK_INT < 21 || powerManager == null || !powerManager.isPowerSaveMode()) {
                                                            String str6 = valueOf4;
                                                            try {
                                                                if (this.isDefaultSms) {
                                                                    Intent intent = new Intent(getApplicationContext(), JPushSmsPopupService.class);
                                                                    intent.putExtra("packageName", str);
                                                                    intent.putExtra("notificationTitle", str3);
                                                                    intent.putExtra("notificationText", valueOf2.toString());
                                                                    intent.putExtra("notificationBigText", str6.toString());
                                                                    intent.putExtra("notificationSubText", valueOf3.toString());
                                                                    intent.putExtra("mStrTimestampMillis", str2);
                                                                    JPushSmsPopupService.enqueueWork(getApplicationContext(), intent);
                                                                } else {
                                                                    Intent intent2 = new Intent(getApplicationContext(), JPushPopupService.class);
                                                                    intent2.putExtra("packageName", str);
                                                                    intent2.putExtra("notificationTitle", str3);
                                                                    intent2.putExtra("notificationText", valueOf2.toString());
                                                                    intent2.putExtra("notificationBigText", str6.toString());
                                                                    intent2.putExtra("notificationSubText", valueOf3.toString());
                                                                    intent2.putExtra("mStrTimestampMillis", str2);
                                                                    JPushPopupService.enqueueWork(getApplicationContext(), intent2);
                                                                }
                                                            } catch (Exception e18) {
                                                                e18.printStackTrace();
                                                            }
                                                        } else {
                                                            if (this.isDefaultSms) {
                                                                DatabaseHelperMissedPushSms instance3 = DatabaseHelperMissedPushSms.getInstance(getApplicationContext());
                                                                try {
                                                                    instance3.onCreateWithTable(instance3.getDB(), DatabaseHelperMissedPushSms.TABLE_NAME);
                                                                } catch (SQLException e19) {
                                                                    e19.printStackTrace();
                                                                }
                                                                PushDataSet pushDataSet = new PushDataSet("", "", "", str, str3, valueOf2, valueOf3, valueOf4, str2, "", "", "", "", "", "", "", "N", "N", SignalLibConsts.g_DataChannel);
                                                                try {
                                                                    instance3.addRow(pushDataSet);
                                                                } catch (Exception e20) {
                                                                    e20.printStackTrace();
                                                                }
                                                            } else {
                                                                String str7 = valueOf4;
                                                                DatabaseHelperMissedNotification instance4 = DatabaseHelperMissedNotification.getInstance(getApplicationContext());
                                                                try {
                                                                    instance4.onCreateWithTable(instance4.getDB(), DatabaseHelperMissedNotification.TABLE_NAME);
                                                                } catch (SQLException e21) {
                                                                    e21.printStackTrace();
                                                                }
                                                                PushDataSet pushDataSet2 = new PushDataSet("", "", "", str, str3, valueOf2, valueOf3, str7, str2, "", "", "", "", "", "", "", "N", "N", SignalLibConsts.g_DataChannel);
                                                                try {
                                                                    instance4.addRow(pushDataSet2);
                                                                } catch (Exception e22) {
                                                                    e22.printStackTrace();
                                                                }
                                                            }
                                                            return;
                                                        }
                                                    }
                                                }
                                                z3 = false;
                                                try {
                                                    length = strArr4.length;
                                                    i = 0;
                                                    while (true) {
                                                        if (i >= length) {
                                                        }
                                                        i++;
                                                    }
                                                } catch (Exception e23) {
                                                    e23.printStackTrace();
                                                }
                                                z = z3;
                                                if (z) {
                                                }
                                            } catch (Exception e24) {
                                                e24.printStackTrace();
                                                stopSelf();
                                                return;
                                            }
                                        } else {
                                            z = false;
                                            this.isDefaultSms = false;
                                            try {
                                                if (!instance.checkHasPackageNameData()) {
                                                    try {
                                                        SignalUtil.getAssetData(2, this);
                                                    } catch (Exception e25) {
                                                        e25.printStackTrace();
                                                    }
                                                }
                                                z = instance.validationPackageName(str);
                                            } catch (Exception e26) {
                                                e26.printStackTrace();
                                            }
                                        }
                                    } else {
                                        z = false;
                                    }
                                    str3 = valueOf;
                                    if (z) {
                                    }
                                } else {
                                    SignalUtil.PRINT_LOG(this.TAG, "\uc0bc\uc131\ud398\uc774 \uc11c\ube44\uc2a4 \uc2e4\ud589 return");
                                    stopSelf();
                                    return;
                                }
                            } else {
                                return;
                            }
                        } else {
                            return;
                        }
                    } catch (Exception e27) {
                        e27.printStackTrace();
                        return;
                    }
                }
            } catch (Exception e28) {
                e28.printStackTrace();
                return;
            }
        }
        stopSelf();
    }

    private boolean isPrivateNumber(String[] strArr, String str) throws Exception {
        int i = 0;
        while (i < strArr.length) {
            if (!str.startsWith(strArr[i])) {
                i++;
            } else if (str.equals("019114") || str.equals("016114") || str.equals("011114")) {
                return false;
            } else {
                return true;
            }
        }
        return false;
    }

    private boolean checkClientExceptionRule(String str, String str2, String str3, String str4) {
        boolean z;
        String string = this.mPrefs.getString(SignalLibConsts.PREF_CLIENT_EXCEPTION_SETTING);
        if (string.length() <= 0) {
            try {
                string = readFromAssets("client-setting.json");
                this.mPrefs.putString(SignalLibConsts.PREF_CLIENT_EXCEPTION_SETTING, string);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        ComparePushDs comparePushDs = ((ResponseResultUrl) new GsonBuilder().disableHtmlEscaping().create().fromJson(string, ResponseResultUrl.class)).getException_pattern().getComparePushDs();
        PushContentArrayDs contains = comparePushDs.getContains();
        PushContentArrayDs equal = comparePushDs.getEqual();
        PushContentArrayDs starts_with = comparePushDs.getStarts_with();
        if (equal != null) {
            ArrayList<String> text = equal.getText();
            if (text != null) {
                int i = 0;
                while (true) {
                    if (i >= text.size()) {
                        break;
                    }
                    try {
                        if (str3.contentEquals(text.get(i))) {
                            StringBuilder sb = new StringBuilder();
                            sb.append("RULE equal : ");
                            sb.append(str3);
                            sb.toString();
                            z = true;
                            break;
                        }
                        i++;
                    } catch (Exception e2) {
                        e2.printStackTrace();
                    }
                }
            }
        }
        z = false;
        if (contains != null) {
            ArrayList<String> text2 = contains.getText();
            if (text2 != null) {
                int i2 = 0;
                while (true) {
                    if (i2 >= text2.size()) {
                        break;
                    }
                    try {
                        if (str3.contains(text2.get(i2))) {
                            StringBuilder sb2 = new StringBuilder();
                            sb2.append("RULE contains : ");
                            sb2.append(str3);
                            sb2.toString();
                            z = true;
                            break;
                        }
                        i2++;
                    } catch (Exception e3) {
                        e3.printStackTrace();
                    }
                }
            }
        }
        if (starts_with != null) {
            ArrayList<String> text3 = starts_with.getText();
            if (text3 != null) {
                int i3 = 0;
                while (true) {
                    if (i3 >= text3.size()) {
                        break;
                    }
                    try {
                        if (str3.startsWith(text3.get(i3))) {
                            StringBuilder sb3 = new StringBuilder();
                            sb3.append("RULE startsWith : ");
                            sb3.append(str3);
                            sb3.toString();
                            z = true;
                            break;
                        }
                        i3++;
                    } catch (Exception e4) {
                        e4.printStackTrace();
                    }
                }
            }
        }
        if (equal != null) {
            ArrayList<String> title = equal.getTitle();
            if (title != null) {
                int i4 = 0;
                while (true) {
                    if (i4 >= title.size()) {
                        break;
                    }
                    try {
                        if (str2.contentEquals(title.get(i4))) {
                            StringBuilder sb4 = new StringBuilder();
                            sb4.append("TITLE RULE contentEquals : ");
                            sb4.append(str2);
                            sb4.toString();
                            z = true;
                            break;
                        }
                        i4++;
                    } catch (Exception e5) {
                        e5.printStackTrace();
                    }
                }
            }
        }
        if (contains != null) {
            ArrayList<String> title2 = contains.getTitle();
            if (title2 != null) {
                int i5 = 0;
                while (true) {
                    if (i5 >= title2.size()) {
                        break;
                    }
                    try {
                        if (str2.contains(title2.get(i5))) {
                            StringBuilder sb5 = new StringBuilder();
                            sb5.append("TITLE RULE contains : ");
                            sb5.append(str2);
                            sb5.toString();
                            z = true;
                            break;
                        }
                        i5++;
                    } catch (Exception e6) {
                        e6.printStackTrace();
                    }
                }
            }
        }
        if (starts_with != null) {
            ArrayList<String> title3 = starts_with.getTitle();
            if (title3 != null) {
                int i6 = 0;
                while (true) {
                    if (i6 >= title3.size()) {
                        break;
                    }
                    try {
                        if (str2.startsWith(title3.get(i6))) {
                            StringBuilder sb6 = new StringBuilder();
                            sb6.append("TITLE RULE startsWith : ");
                            sb6.append(str2);
                            sb6.toString();
                            z = true;
                            break;
                        }
                        i6++;
                    } catch (Exception e7) {
                        e7.printStackTrace();
                    }
                }
            }
        }
        if (equal != null) {
            ArrayList<String> big_text = equal.getBig_text();
            if (big_text != null) {
                int i7 = 0;
                while (true) {
                    if (i7 >= big_text.size()) {
                        break;
                    }
                    try {
                        if (str4.contentEquals(big_text.get(i7))) {
                            StringBuilder sb7 = new StringBuilder();
                            sb7.append("BIGTEXT RULE startsWith : ");
                            sb7.append(str4);
                            sb7.toString();
                            z = true;
                            break;
                        }
                        i7++;
                    } catch (Exception e8) {
                        e8.printStackTrace();
                    }
                }
            }
        }
        if (contains != null) {
            ArrayList<String> big_text2 = contains.getBig_text();
            if (big_text2 != null) {
                int i8 = 0;
                while (true) {
                    if (i8 >= big_text2.size()) {
                        break;
                    }
                    try {
                        if (str4.contains(big_text2.get(i8))) {
                            StringBuilder sb8 = new StringBuilder();
                            sb8.append("BIGTEXT RULE contains : ");
                            sb8.append(str4);
                            sb8.toString();
                            z = true;
                            break;
                        }
                        i8++;
                    } catch (Exception e9) {
                        e9.printStackTrace();
                    }
                }
            }
        }
        if (starts_with != null) {
            ArrayList<String> big_text3 = starts_with.getBig_text();
            if (big_text3 != null) {
                int i9 = 0;
                while (true) {
                    if (i9 >= big_text3.size()) {
                        break;
                    }
                    try {
                        if (str4.startsWith(big_text3.get(i9))) {
                            StringBuilder sb9 = new StringBuilder();
                            sb9.append("BIGTEXT RULE startsWith : ");
                            sb9.append(str4);
                            sb9.toString();
                            z = true;
                            break;
                        }
                        i9++;
                    } catch (Exception e10) {
                        e10.printStackTrace();
                    }
                }
            }
        }
        ArrayList<PushPatternContentDs> pattern = comparePushDs.getPattern();
        if (pattern != null) {
            int i10 = 0;
            loop9:
            while (true) {
                if (i10 >= pattern.size()) {
                    break;
                }
                if (str.equals(pattern.get(i10).getPackageNm())) {
                    ArrayList<PushContentDs> pattern2 = pattern.get(i10).getPattern();
                    for (int i11 = 0; i11 < pattern2.size(); i11++) {
                        String NULL_TO_STRING = SignalUtil.NULL_TO_STRING(pattern2.get(i11).getTitle());
                        if (Pattern.matches(NULL_TO_STRING, str2)) {
                            StringBuilder sb10 = new StringBuilder();
                            sb10.append("PATTERN RULE title: ");
                            sb10.append(NULL_TO_STRING);
                            sb10.toString();
                            break loop9;
                        }
                        String NULL_TO_STRING2 = SignalUtil.NULL_TO_STRING(pattern2.get(i11).getText());
                        if (Pattern.matches(NULL_TO_STRING2, str3)) {
                            StringBuilder sb11 = new StringBuilder();
                            sb11.append("PATTERN RULE text: ");
                            sb11.append(NULL_TO_STRING2);
                            sb11.toString();
                            break loop9;
                        }
                        String NULL_TO_STRING3 = SignalUtil.NULL_TO_STRING(pattern2.get(i11).getBig_text());
                        if (Pattern.matches(NULL_TO_STRING3, str4)) {
                            StringBuilder sb12 = new StringBuilder();
                            sb12.append("PATTERN RULE bigText: ");
                            sb12.append(NULL_TO_STRING3);
                            sb12.toString();
                            break loop9;
                        }
                    }
                    continue;
                }
                i10++;
            }
            z = true;
        }
        return z;
    }

    private String readFromAssets(String str) throws Exception {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(getAssets().open(str)));
        StringBuilder sb = new StringBuilder();
        for (String readLine = bufferedReader.readLine(); readLine != null; readLine = bufferedReader.readLine()) {
            sb.append(readLine);
        }
        bufferedReader.close();
        return sb.toString();
    }

    /* JADX WARNING: Removed duplicated region for block: B:24:0x0044 A[SYNTHETIC, Splitter:B:24:0x0044] */
    /* JADX WARNING: Removed duplicated region for block: B:32:0x0051 A[SYNTHETIC, Splitter:B:32:0x0051] */
    private String loadAssetTextAsString(Context context, String str) {
        BufferedReader bufferedReader;
        BufferedReader bufferedReader2 = null;
        try {
            StringBuilder sb = new StringBuilder();
            bufferedReader = new BufferedReader(new InputStreamReader(context.getAssets().open(str)));
            boolean z = true;
            while (true) {
                try {
                    String readLine = bufferedReader.readLine();
                    if (readLine == null) {
                        break;
                    }
                    if (z) {
                        z = false;
                    } else {
                        sb.append(10);
                    }
                    sb.append(readLine);
                } catch (IOException e) {
                    e = e;
                    try {
                        e.printStackTrace();
                        if (bufferedReader != null) {
                            try {
                                bufferedReader.close();
                            } catch (IOException e2) {
                                e2.printStackTrace();
                            }
                        }
                        return null;
                    } catch (Throwable th) {
                        th = th;
                        bufferedReader2 = bufferedReader;
                        if (bufferedReader2 != null) {
                        }
                        throw th;
                    }
                }
            }
            String sb2 = sb.toString();
            try {
                bufferedReader.close();
            } catch (IOException e3) {
                e3.printStackTrace();
            }
            return sb2;
        } catch (IOException e4) {
            e = e4;
            bufferedReader = null;
            e.printStackTrace();
            if (bufferedReader != null) {
            }
            return null;
        } catch (Throwable th2) {
            th = th2;
            if (bufferedReader2 != null) {
                try {
                    bufferedReader2.close();
                } catch (IOException e5) {
                    e5.printStackTrace();
                }
            }
            throw th;
        }
    }
}