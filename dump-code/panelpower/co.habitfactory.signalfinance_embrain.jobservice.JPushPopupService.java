package co.habitfactory.signalfinance_embrain.jobservice;

import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.Build.VERSION;
import android.provider.Settings.Secure;
import android.util.Log;
import androidx.core.app.NotificationCompat.BigTextStyle;
import androidx.core.app.NotificationCompat.Builder;
import androidx.core.app.SafeJobIntentService;
import co.habitfactory.signalfinance_embrain.R;
import co.habitfactory.signalfinance_embrain.comm.ResultCode;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalLibPrefs;
import co.habitfactory.signalfinance_embrain.comm.SignalUtil;
import co.habitfactory.signalfinance_embrain.dataset.PushDataSet;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperMissedNotification;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperPush;
import co.habitfactory.signalfinance_embrain.retroapi.APIHelper;
import co.habitfactory.signalfinance_embrain.retroapi.RestfulAdapter;
import co.habitfactory.signalfinance_embrain.retroapi.request.sms.IptSavePushData;
import co.habitfactory.signalfinance_embrain.retroapi.response.layout.sms.OptSaveSmsData;
import co.habitfactory.signalfinance_embrain.service.NotificationBuilder;
import com.embrain.panelpower.IConstValue.AppBannerConst;
import com.embrain.panelpower.UserInfoManager;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class JPushPopupService extends SafeJobIntentService implements SignalLibConsts {
    static final int JOB_ID = 1012;
    /* access modifiers changed from: private */
    public final String TAG = JPushPopupService.class.getSimpleName();
    private Context mContext;
    private long mLongRowId;
    private SignalLibPrefs mPrefs;
    private PushDataSet mPushDs;

    public void onCreate() {
        super.onCreate();
        this.mPrefs = new SignalLibPrefs(this);
        this.mContext = this;
    }

    public static void enqueueWork(Context context, Intent intent) {
        enqueueWork(context, JPushPopupService.class, 1012, intent);
    }

    /* access modifiers changed from: protected */
    public void onHandleWork(Intent intent) {
        if (this.mPrefs.getBoolean(SignalLibConsts.PREF_STOP_COLLECT, Boolean.valueOf(true)).booleanValue()) {
            Log.d("\uc218\uc9d1\uc815\uc9c0", " : \ud478\uc2dc\ud31d\uc5c5 \ub3d9\uc791 \uc548\ud568.");
            return;
        }
        String str = null;
        try {
            str = SignalUtil.getUserId(this);
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (str != null && str.length() > 0) {
            try {
                savePushData(SignalUtil.NULL_TO_STRING(intent.getStringExtra("packageName")), SignalUtil.NULL_TO_STRING(intent.getStringExtra("notificationTitle")), SignalUtil.NULL_TO_STRING(intent.getStringExtra("notificationText")), SignalUtil.NULL_TO_STRING(intent.getStringExtra("notificationSubText")), SignalUtil.NULL_TO_STRING(intent.getStringExtra("notificationBigText")), SignalUtil.NULL_TO_STRING(intent.getStringExtra("mStrTimestampMillis")));
            } catch (Exception e2) {
                e2.printStackTrace();
                stopSelf();
            }
        }
    }

    private void savePushData(String str, String str2, String str3, String str4, String str5, String str6) throws Exception {
        String str7;
        DatabaseHelperPush instance = DatabaseHelperPush.getInstance(getApplicationContext());
        try {
            instance.onCreateWithTable(instance.getDB(), DatabaseHelperPush.TABLE_NAME);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        this.mPushDs = null;
        try {
            str7 = SignalUtil.getDeviceLineNumber(this);
        } catch (Exception e2) {
            e2.printStackTrace();
            str7 = "";
        }
        String str8 = str7;
        try {
            if (!chkGpsService()) {
                PushDataSet pushDataSet = new PushDataSet("", "", str8, str, str2, str3, str4, str5, str6, "", "", "OFF", "OFF", "", "OFF", SignalUtil.getCurrentTime("yyyyMMddHHmmssSSS"), "N", UserInfoManager.AGREE_Y, SignalLibConsts.g_DataChannel);
                this.mPushDs = pushDataSet;
            } else {
                PushDataSet pushDataSet2 = new PushDataSet("", "", str8, str, str2, str3, str4, str5, str6, "", "", "PS", "PS", "", "PS", SignalUtil.getCurrentTime("yyyyMMddHHmmssSSS"), "N", UserInfoManager.AGREE_Y, SignalLibConsts.g_DataChannel);
                this.mPushDs = pushDataSet2;
            }
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        try {
            this.mLongRowId = instance.addRow(this.mPushDs);
        } catch (Exception e4) {
            e4.printStackTrace();
        }
        try {
            String userId = SignalUtil.getUserId(this);
            String str9 = !chkGpsService() ? "OFF" : "PS";
            String str10 = str9;
            String str11 = str10;
            IptSavePushData iptSavePushData = new IptSavePushData(userId, this.mPushDs.getUserSimNumber(), this.mPushDs.getPackageNm(), this.mPushDs.getNotiTitle(), this.mPushDs.getNotiText(), this.mPushDs.getNotiSubText(), this.mPushDs.getNotificationBigText(), this.mPushDs.getTimestampMillis(), str9, str10, str11, str11, SignalLibConsts.g_DataChannel);
            requestRetrofit(iptSavePushData);
        } catch (Exception e5) {
            e5.printStackTrace();
        }
    }

    private void requestRetrofit(IptSavePushData iptSavePushData) throws Exception {
        APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this).requestSavePushData(iptSavePushData), 1, new Callback<OptSaveSmsData>() {
            public void onResponse(Call<OptSaveSmsData> call, Response<OptSaveSmsData> response) {
                int code = response.code();
                if (code == 200) {
                    OptSaveSmsData optSaveSmsData = (OptSaveSmsData) response.body();
                    if (optSaveSmsData != null) {
                        String access$000 = JPushPopupService.this.TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("response");
                        sb.append(String.valueOf(code));
                        SignalUtil.PRINT_LOG(access$000, sb.toString());
                        try {
                            JPushPopupService.this.parseResult(optSaveSmsData);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        SignalUtil.PRINT_LOG(JPushPopupService.this.TAG, "response : result null");
                        try {
                            JPushPopupService.this.updateSendToServerDatabase();
                        } catch (Exception e2) {
                            e2.printStackTrace();
                        }
                        JPushPopupService.this.stopSelf();
                    }
                } else {
                    String access$0002 = JPushPopupService.this.TAG;
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("response : ");
                    sb2.append(String.valueOf(code));
                    SignalUtil.PRINT_LOG(access$0002, sb2.toString());
                    try {
                        JPushPopupService.this.updateSendToServerDatabase();
                    } catch (Exception e3) {
                        e3.printStackTrace();
                    }
                    JPushPopupService.this.stopSelf();
                }
            }

            public void onFailure(Call<OptSaveSmsData> call, Throwable th) {
                String access$000 = JPushPopupService.this.TAG;
                StringBuilder sb = new StringBuilder();
                sb.append("fail : ");
                sb.append(th.toString());
                SignalUtil.PRINT_LOG(access$000, sb.toString());
                try {
                    JPushPopupService.this.updateSendToServerDatabase();
                } catch (Exception e) {
                    e.printStackTrace();
                }
                JPushPopupService.this.stopSelf();
            }
        });
    }

    /* JADX WARNING: Removed duplicated region for block: B:100:0x0289  */
    /* JADX WARNING: Removed duplicated region for block: B:93:0x022c  */
    /* JADX WARNING: Removed duplicated region for block: B:94:0x0260  */
    /* JADX WARNING: Removed duplicated region for block: B:99:0x027b  */
    public void parseResult(OptSaveSmsData optSaveSmsData) throws Exception {
        String str;
        String str2;
        String str3;
        String str4;
        String str5;
        String str6;
        String str7;
        String str8 = "";
        String str9 = this.TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("resultcode  : ");
        sb.append(optSaveSmsData.getResultcode());
        SignalUtil.PRINT_LOG(str9, sb.toString());
        String str10 = this.TAG;
        StringBuilder sb2 = new StringBuilder();
        sb2.append("message     : ");
        sb2.append(optSaveSmsData.getMessage());
        SignalUtil.PRINT_LOG(str10, sb2.toString());
        String resultcode = optSaveSmsData.getResultcode();
        if (resultcode.equals("00")) {
            String NULL_TO_STRING = SignalUtil.NULL_TO_STRING(optSaveSmsData.getSmsId());
            String NULL_TO_STRING2 = SignalUtil.NULL_TO_STRING(optSaveSmsData.getGpsStatus());
            String NULL_TO_STRING3 = SignalUtil.NULL_TO_STRING(optSaveSmsData.getrTimestamp());
            if (NULL_TO_STRING2.length() > 0 && "T".equals(NULL_TO_STRING2.toUpperCase())) {
                try {
                    Intent intent = new Intent(getApplicationContext(), JFusedPushLocationService.class);
                    getApplicationContext().stopService(intent);
                    intent.putExtra("pushId", NULL_TO_STRING);
                    intent.putExtra("rowId", this.mLongRowId);
                    intent.putExtra("rTimestamp", NULL_TO_STRING3);
                    JFusedPushLocationService.enqueueWork(getApplicationContext(), intent);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            try {
                String NULL_TO_STRING4 = SignalUtil.NULL_TO_STRING(optSaveSmsData.getCategoryCode());
                if (SignalUtil.checkCategoryForShowNoti(1, NULL_TO_STRING4)) {
                    try {
                        str = SignalUtil.NULL_TO_STRING(optSaveSmsData.getParseType());
                    } catch (Exception e2) {
                        e2.printStackTrace();
                        str = str8;
                    }
                    if ((str != null || str.length() >= 0) && !"CS".equals(str) && !"PY".equals(str) && !"FD".equals(str) && !"LN".equals(str) && !"SP".equals(str) && !"EX".equals(str)) {
                        if ("CD".equals(str)) {
                            String NULL_TO_STRING5 = SignalUtil.NULL_TO_STRING(this.mPrefs.getString(SignalLibConsts.PREF_IS_CARD_NOTI_OFF));
                            if (NULL_TO_STRING5.length() > 0 && "OFF".equals(NULL_TO_STRING5)) {
                                return;
                            }
                        } else if ("BK".equals(str)) {
                            String NULL_TO_STRING6 = SignalUtil.NULL_TO_STRING(this.mPrefs.getString(SignalLibConsts.PREF_IS_BANK_NOTI_OFF));
                            if (NULL_TO_STRING6.length() > 0 && "OFF".equals(NULL_TO_STRING6)) {
                                return;
                            }
                        }
                        try {
                            str2 = SignalUtil.NULL_TO_STRING(optSaveSmsData.getCardApprovalType());
                        } catch (Exception e3) {
                            e3.printStackTrace();
                            str2 = str8;
                        }
                        String str11 = "\ud574\uc678";
                        if ("CD".equals(str)) {
                            if (!str2.startsWith(AppBannerConst.PATH_MENU_TP_FUN)) {
                                str11 = str8;
                            }
                            if (str2.endsWith("C")) {
                                StringBuilder sb3 = new StringBuilder();
                                sb3.append(str11);
                                sb3.append("\ucde8\uc18c");
                                str3 = sb3.toString();
                            } else {
                                str3 = str11;
                            }
                            if (str3.length() > 0) {
                                StringBuilder sb4 = new StringBuilder();
                                sb4.append("[");
                                sb4.append(str3);
                                sb4.append("] ");
                                str3 = sb4.toString();
                            }
                        } else if ("BK".equals(str)) {
                            if (!str2.startsWith(AppBannerConst.PATH_MENU_TP_FUN)) {
                                str11 = str8;
                            }
                            if (str2.endsWith("W")) {
                                StringBuilder sb5 = new StringBuilder();
                                sb5.append(str11);
                                sb5.append("\ucd9c\uae08");
                                str7 = sb5.toString();
                            } else if (str2.endsWith("D")) {
                                StringBuilder sb6 = new StringBuilder();
                                sb6.append(str11);
                                sb6.append("\uc785\uae08");
                                str7 = sb6.toString();
                            } else {
                                str7 = str11;
                            }
                            if (str3.length() > 0) {
                                StringBuilder sb7 = new StringBuilder();
                                sb7.append("[");
                                sb7.append(str3);
                                sb7.append("] ");
                                str3 = sb7.toString();
                            }
                        } else {
                            str3 = str8;
                        }
                        String NULL_TO_STRING7 = SignalUtil.NULL_TO_STRING(optSaveSmsData.getCardApprovalStore());
                        String makeMoneyComma = SignalUtil.makeMoneyComma(SignalUtil.NULL_TO_STRING(optSaveSmsData.getCardApprovalPrice()));
                        if (makeMoneyComma.length() > 0) {
                            try {
                                str5 = SignalUtil.makeMoneyComma(SignalUtil.NULL_TO_STRING(optSaveSmsData.getCategoryMonthSum()));
                                try {
                                    str8 = SignalUtil.NULL_TO_STRING(optSaveSmsData.getCategoryName());
                                } catch (Exception e4) {
                                    e = e4;
                                    e.printStackTrace();
                                    if (str5.length() > 0) {
                                    }
                                    str4 = str6;
                                    if (VERSION.SDK_INT > 24) {
                                    }
                                    closeDb();
                                    stopSelf();
                                }
                            } catch (Exception e5) {
                                e = e5;
                                str5 = str8;
                                e.printStackTrace();
                                if (str5.length() > 0) {
                                }
                                str4 = str6;
                                if (VERSION.SDK_INT > 24) {
                                }
                                closeDb();
                                stopSelf();
                            }
                            if (str5.length() > 0) {
                                StringBuilder sb8 = new StringBuilder();
                                sb8.append(" (");
                                sb8.append(str8);
                                sb8.append(" \uc6d4 \ud569\uacc4 : ");
                                sb8.append(str5);
                                sb8.append("\uc6d0)");
                                String sb9 = sb8.toString();
                                StringBuilder sb10 = new StringBuilder();
                                sb10.append(str3);
                                sb10.append(makeMoneyComma);
                                sb10.append("\uc6d0");
                                sb10.append(sb9);
                                str6 = sb10.toString();
                            } else {
                                StringBuilder sb11 = new StringBuilder();
                                sb11.append(str3);
                                sb11.append(makeMoneyComma);
                                sb11.append("\uc6d0");
                                str6 = sb11.toString();
                            }
                            str4 = str6;
                        } else {
                            str4 = makeMoneyComma;
                        }
                        if (VERSION.SDK_INT > 24) {
                            NotificationBuilder.newInstance(this.mContext).sendBundledNotification(NULL_TO_STRING, str, NULL_TO_STRING4, NULL_TO_STRING7, str4, SignalLibConsts.PREF_API_SMS_ONLINE_NOTIFICATION_ID, 1);
                        } else {
                            setNotification(NULL_TO_STRING, str, NULL_TO_STRING4, NULL_TO_STRING7, str4, SignalLibConsts.PREF_API_SMS_ONLINE_NOTIFICATION_ID);
                        }
                    } else {
                        return;
                    }
                } else {
                    return;
                }
            } catch (Exception e6) {
                e6.printStackTrace();
                return;
            }
        } else if (resultcode.equals(ResultCode.MESSAGE_m01) || resultcode.equals(ResultCode.MESSAGE_m02) || resultcode.equals(ResultCode.MESSAGE_m04) || resultcode.equals(ResultCode.MESSAGE_m05) || resultcode.equals(ResultCode.MESSAGE_m06) || resultcode.equals(ResultCode.MESSAGE_m07) || resultcode.equals(ResultCode.MESSAGE_m19) || resultcode.equals(ResultCode.MESSAGE_m37) || resultcode.equals(ResultCode.MESSAGE_m8888)) {
            updateSendToServerDatabase();
            String str12 = this.TAG;
            StringBuilder sb12 = new StringBuilder();
            sb12.append("resultcode : ");
            sb12.append(resultcode);
            sb12.append(" / reTry");
            SignalUtil.PRINT_LOG(str12, sb12.toString());
        }
        closeDb();
        stopSelf();
    }

    public void setNotification(String str, String str2, String str3, String str4, String str5, int i) {
        Bitmap bitmap;
        StringBuilder sb = new StringBuilder();
        sb.append("signalembrain://action_signal?");
        sb.append(SignalLibConsts.SCHEME_LINK_ID);
        sb.append("=");
        sb.append(str);
        Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(sb.toString()));
        intent.addFlags(268468224);
        PendingIntent activity = PendingIntent.getActivity(getApplicationContext(), 0, intent, 134217728);
        Builder builder = new Builder(getApplicationContext());
        if ("BK".equals(str2)) {
            bitmap = null;
        } else {
            bitmap = BitmapFactory.decodeResource(getApplicationContext().getResources(), setCategoryImg(str3, "_c"));
        }
        BigTextStyle bigTextStyle = new BigTextStyle();
        bigTextStyle.bigText(str5);
        if (str4 == null || str4.length() < 0) {
            str4 = "\ud478\uc2dc\uc54c\ub9bc";
        }
        bigTextStyle.setBigContentTitle(str4);
        builder.setAutoCancel(true).setDefaults(-1).setWhen(System.currentTimeMillis()).setLargeIcon(bitmap).setSmallIcon(R.drawable.icon_signal_negative).setTicker("").setContentTitle(str4).setContentText(str5).setDefaults(5).setVibrate(new long[]{0}).setContentIntent(activity).setContentInfo("").setColor(getResources().getColor(R.color.signalnoticolor)).setStyle(bigTextStyle);
        ((NotificationManager) getApplicationContext().getSystemService("notification")).notify(i, builder.build());
    }

    public int setCategoryImg(String str, String str2) {
        int i = 0;
        try {
            if (str.length() == 5) {
                str = str.substring(0, 3);
            }
            Resources resources = getResources();
            StringBuilder sb = new StringBuilder();
            sb.append("icon_category_");
            sb.append(str);
            sb.append(str2);
            i = resources.getIdentifier(sb.toString(), "drawable", getPackageName());
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (i != 0) {
            return i;
        }
        Resources resources2 = getResources();
        StringBuilder sb2 = new StringBuilder();
        sb2.append("icon_category_017");
        sb2.append(str2);
        return resources2.getIdentifier(sb2.toString(), "drawable", getPackageName());
    }

    /* access modifiers changed from: private */
    public void updateSendToServerDatabase() throws Exception {
        DatabaseHelperMissedNotification instance = DatabaseHelperMissedNotification.getInstance(getApplicationContext());
        try {
            instance.onCreateWithTable(instance.getDB(), DatabaseHelperMissedNotification.TABLE_NAME);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        if (!(this.mPushDs.getPackageNm() == null && this.mPushDs.getNotiText() == null && this.mPushDs.getNotiText().length() <= 0) && !instance.checkBodyRowExist(this.mPushDs.getNotiTitle(), this.mPushDs.getNotiText(), this.mPushDs.getPackageNm()).booleanValue()) {
            PushDataSet pushDataSet = new PushDataSet("", "", "", this.mPushDs.getPackageNm(), this.mPushDs.getNotiTitle(), this.mPushDs.getNotiText(), this.mPushDs.getNotiSubText(), this.mPushDs.getNotificationBigText(), this.mPushDs.getTimestampMillis(), "", "", "", "", "", "", "", "N", "N", SignalLibConsts.g_DataChannel);
            try {
                instance.addRow(pushDataSet);
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    private boolean chkGpsService() {
        String string = Secure.getString(getContentResolver(), "location_providers_allowed");
        return string.matches(".*gps.*") && string.matches(".*network.*");
    }

    public void onDestroy() {
        super.onDestroy();
        closeDb();
    }

    private void closeDb() {
        try {
            SQLiteDatabase db = DatabaseHelperPush.getInstance(getApplicationContext()).getDB();
            if (db != null) {
                db.close();
            }
        } catch (SQLiteException e) {
            e.printStackTrace();
        }
    }
}