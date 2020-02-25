package com.embrain.panelpower.fcm;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.graphics.BitmapFactory;
import android.os.Build.VERSION;
import android.util.Log;
import androidx.core.app.NotificationCompat.BigTextStyle;
import androidx.core.app.NotificationCompat.Builder;
import com.embrain.panelbigdata.EmBigDataManager;
import com.embrain.panelbigdata.utils.LogUtil;
import com.embrain.panelbigdata.utils.StringUtils;
import com.embrain.panelpower.PushPopupActivity;
import com.embrain.panelpower.R;
import com.embrain.panelpower.SplashActivity;
import com.embrain.panelpower.SurveyActivity;
import com.embrain.panelpower.UserInfoManager;
import com.embrain.panelpower.networks.HttpManager;
import com.embrain.panelpower.networks.vo.AlarmListVo;
import com.embrain.panelpower.networks.vo.ResponseAlarmList;
import com.embrain.panelpower.networks.vo.ResponseSurveyExpress;
import com.embrain.panelpower.networks.vo.SurveyExpressVO;
import com.embrain.panelpower.utils.PanelPreferenceUtils;
import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;
import com.google.gson.Gson;
import java.io.IOException;
import java.util.Map;
import me.leolin.shortcutbadger.ShortcutBadger;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class FireBaseMessagingService extends FirebaseMessagingService implements FCMDataConstants {
    private static final int NOTIFICATION_ID = 1058198720;
    private static final String TAG = "MyFirebaseMsgService";
    private String ChannelId = "embrain_channel_id";
    private String ChannelSeqNm = "embrain_seq_nm";

    private class PushData {
        String anotherUrl;
        String is_banner;
        String is_popup;
        String is_what;
        String msg;
        String psid;
        String survey_alias;
        String survey_id;
        String type;

        private PushData(RemoteMessage remoteMessage) {
            Map<String, String> data = remoteMessage.getData();
            this.type = data.get(FCMDataConstants.DATA_PUSH_NUM);
            this.survey_alias = data.get(FCMDataConstants.DATA_REF_PK);
            this.msg = data.get("msg");
            this.survey_id = data.get(FCMDataConstants.DATA_PU_IDX);
            this.is_banner = data.get(FCMDataConstants.DATA_PUSH_TYPE1);
            this.is_popup = data.get(FCMDataConstants.DATA_PUSH_TYPE2);
            this.is_what = data.get(FCMDataConstants.DATA_PUSH_TYPE2);
            this.anotherUrl = data.get(FCMDataConstants.DATA_ANOTHER_URL);
            this.psid = data.get(FCMDataConstants.DATA_PSID);
        }
    }

    public void onMessageReceived(RemoteMessage remoteMessage) {
        StringBuilder sb = new StringBuilder();
        sb.append("push message received : ");
        sb.append(remoteMessage.getMessageId());
        Log.e(TAG, sb.toString());
        StringBuilder sb2 = new StringBuilder();
        sb2.append("push message received : ");
        sb2.append(remoteMessage.getMessageId());
        LogUtil.write(sb2.toString());
        try {
            if (remoteMessage.getData().size() > 0) {
                StringBuilder sb3 = new StringBuilder();
                sb3.append("MyFirebaseMsgService============Message data payload============: ");
                sb3.append(remoteMessage.getData());
                LogUtil.write(sb3.toString());
                if (FCMDataConstants.VALUE_TYPE_BIG_DATA.equals(remoteMessage.getData().get("type"))) {
                    processBigdata(remoteMessage);
                } else {
                    processPanelpower(remoteMessage);
                }
                EmBigDataManager.start(getApplicationContext(), true);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void onNewToken(String str) {
        super.onNewToken(str);
        PanelPreferenceUtils.setPushToken(getApplicationContext(), str);
    }

    private void processBigdata(RemoteMessage remoteMessage) {
        Map<String, String> data = remoteMessage.getData();
        String str = data.get(FCMDataConstants.DATA_KEY_EXECUTE);
        if (FCMDataConstants.VALUE_BIG_DATA_SESSION.equals(str)) {
            LogUtil.write("big data push received : session");
            EmBigDataManager.requestBigdataSession(getApplicationContext(), remoteMessage.getMessageId(), UserInfoManager.getInstance(getApplicationContext()).getPanelId(), PanelPreferenceUtils.getAdId(getApplicationContext()));
            return;
        }
        if ("stop".equals(str)) {
            LogUtil.write("big data push received : stop");
            stopBigData(data.get(FCMDataConstants.DATA_KEY_DATA_TYPE));
        }
    }

    private void stopBigData(String str) {
        if (FCMDataConstants.VALUE_DATA_TYPE_ALL.equals(str)) {
            EmBigDataManager.stopUsageJob(getBaseContext());
            EmBigDataManager.stopLocationJob(getBaseContext());
        } else if (FCMDataConstants.VALUE_DATA_TYPE_USAGE.equals(str)) {
            EmBigDataManager.stopUsageJob(getBaseContext());
        } else if ("location".equals(str)) {
            EmBigDataManager.stopLocationJob(getBaseContext());
        }
    }

    private void processPanelpower(RemoteMessage remoteMessage) {
        PushData pushData = new PushData(remoteMessage);
        if (!StringUtils.isEmpty(pushData.survey_id)) {
            checkSurveyExpress(pushData);
        } else {
            processPush(pushData);
        }
    }

    private void checkSurveyExpress(final PushData pushData) {
        SurveyExpressVO surveyExpressVO = new SurveyExpressVO();
        surveyExpressVO.panelId = UserInfoManager.getInstance(getApplicationContext()).getPanelId();
        surveyExpressVO.puIdx = pushData.survey_id;
        HttpManager.getInstance().requestSurveyExpress(surveyExpressVO, new Callback() {
            public void onFailure(Call call, IOException iOException) {
                FireBaseMessagingService.this.processPush(pushData);
            }

            public void onResponse(Call call, Response response) throws IOException {
                try {
                    ResponseSurveyExpress responseSurveyExpress = (ResponseSurveyExpress) new Gson().fromJson(response.body().string(), ResponseSurveyExpress.class);
                    if (responseSurveyExpress.isSuccess()) {
                        if (responseSurveyExpress.surveyexpress != null) {
                            if (responseSurveyExpress.getSurveyexpress().size() != 0) {
                                pushData.anotherUrl = responseSurveyExpress.getSurveyexpress().get(0).surveyexpress;
                                LogUtil.write("checkSurveyExpress =========");
                                StringBuilder sb = new StringBuilder();
                                sb.append("anotherUrl : ");
                                sb.append(pushData.anotherUrl);
                                LogUtil.write(sb.toString());
                                StringBuilder sb2 = new StringBuilder();
                                sb2.append("refPk : ");
                                sb2.append(pushData.survey_alias);
                                LogUtil.write(sb2.toString());
                            }
                        }
                        pushData.anotherUrl = "";
                        LogUtil.write("checkSurveyExpress =========");
                        StringBuilder sb3 = new StringBuilder();
                        sb3.append("anotherUrl : ");
                        sb3.append(pushData.anotherUrl);
                        LogUtil.write(sb3.toString());
                        StringBuilder sb22 = new StringBuilder();
                        sb22.append("refPk : ");
                        sb22.append(pushData.survey_alias);
                        LogUtil.write(sb22.toString());
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } catch (Throwable th) {
                    FireBaseMessagingService.this.processPush(pushData);
                    throw th;
                }
                FireBaseMessagingService.this.processPush(pushData);
            }
        });
    }

    /* access modifiers changed from: private */
    public void processPush(PushData pushData) {
        if (StringUtils.isYn(pushData.is_popup)) {
            showPopup(pushData.type, pushData.msg, pushData.survey_alias, pushData.anotherUrl);
        }
        checkBadgeCnt(pushData);
    }

    private void checkBadgeCnt(final PushData pushData) {
        HttpManager.getInstance().requestAlarmList(new AlarmListVo(UserInfoManager.getInstance(getApplicationContext()).getPanelId()), new Callback() {
            public void onFailure(Call call, IOException iOException) {
                FireBaseMessagingService.this.sendNotification(pushData.type, pushData.msg, pushData.survey_alias, pushData.anotherUrl, 0);
            }

            public void onResponse(Call call, Response response) throws IOException {
                try {
                    ResponseAlarmList responseAlarmList = (ResponseAlarmList) new Gson().fromJson(response.body().string(), ResponseAlarmList.class);
                    FireBaseMessagingService.this.sendNotification(pushData.type, pushData.msg, pushData.survey_alias, pushData.anotherUrl, responseAlarmList.isSuccess() ? responseAlarmList.noCnt : 0);
                } catch (Exception e) {
                    e.printStackTrace();
                    FireBaseMessagingService.this.sendNotification(pushData.type, pushData.msg, pushData.survey_alias, pushData.anotherUrl, 0);
                } catch (Throwable th) {
                    FireBaseMessagingService.this.sendNotification(pushData.type, pushData.msg, pushData.survey_alias, pushData.anotherUrl, 0);
                    throw th;
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void sendNotification(String str, String str2, String str3, String str4, int i) {
        String str5 = str;
        int i2 = i;
        String str6 = "";
        String str7 = StringUtils.isEmpty(str3) ? str6 : str3;
        if (!StringUtils.isEmpty(str4)) {
            str6 = str4;
        }
        String str8 = "beacon".equals(str5) ? getSplitMessage(str2)[1] : str2;
        NotificationManager notificationManager = (NotificationManager) getSystemService("notification");
        PendingIntent activity = PendingIntent.getActivity(this, 0, getNotificationIntent(str5, str2, str7, str6), 1073741824);
        if (VERSION.SDK_INT >= 26) {
            NotificationChannel notificationChannel = new NotificationChannel(this.ChannelId, this.ChannelSeqNm, 3);
            notificationChannel.setShowBadge(false);
            notificationManager.createNotificationChannel(notificationChannel);
            notificationManager.notify(NOTIFICATION_ID, new Builder(this, this.ChannelId).setLargeIcon(BitmapFactory.decodeResource(getResources(), R.mipmap.ic_launcher)).setSmallIcon(R.drawable.icon_status).setTicker(getString(R.string.app_name)).setContentTitle(getString(R.string.app_name)).setContentText(str8).setStyle(new BigTextStyle().bigText(str8)).setColor(getResources().getColor(R.color.primary)).setNumber(i2).setBadgeIconType(1).setDefaults(7).setAutoCancel(true).setContentIntent(activity).build());
            return;
        }
        notificationManager.notify(NOTIFICATION_ID, new Builder(this).setLargeIcon(BitmapFactory.decodeResource(getResources(), R.mipmap.ic_launcher)).setSmallIcon(R.drawable.icon_status).setTicker(getString(R.string.app_name)).setContentTitle(getString(R.string.app_name)).setContentText(str8).setStyle(new BigTextStyle().bigText(str8)).setColor(getResources().getColor(R.color.primary)).setDefaults(7).setAutoCancel(true).setContentIntent(activity).build());
        setBadge(getBaseContext(), i2);
    }

    private Intent getNotificationIntent(String str, String str2, String str3, String str4) {
        if (!"josa".equals(str) || StringUtils.isEmpty(str3)) {
            Intent intent = new Intent(this, SplashActivity.class);
            intent.addFlags(268435456);
            intent.putExtra("type", str);
            intent.putExtra("msg", str2);
            intent.putExtra(PushPopupActivity.EXTRA_PUSH_SURVEY_ALIAS, str3);
            intent.putExtra("url", str4);
            return intent;
        }
        Intent intent2 = new Intent(this, SurveyActivity.class);
        intent2.addFlags(268435456);
        intent2.putExtra(SurveyActivity.EXTRA_SURVEY_ID, str3);
        return intent2;
    }

    public static void setBadge(Context context, int i) {
        Intent intent = new Intent("android.intent.action.BADGE_COUNT_UPDATE");
        intent.putExtra("badge_count", i);
        intent.putExtra("badge_count_package_name", context.getPackageName());
        intent.putExtra("badge_count_class_name", SplashActivity.class.getName());
        context.sendBroadcast(intent);
        ShortcutBadger.applyCount(context, i);
    }

    public static void clearBadge(Context context) {
        ((NotificationManager) context.getSystemService("notification")).cancelAll();
        ShortcutBadger.removeCount(context);
    }

    private void showPopup(String str, String str2, String str3, String str4) {
        if (StringUtils.isEmpty(str3)) {
            str3 = "";
        }
        Intent intent = new Intent(this, PushPopupActivity.class);
        intent.addFlags(1484783616);
        intent.putExtra("type", str);
        intent.putExtra("msg", str2);
        intent.putExtra(PushPopupActivity.EXTRA_PUSH_SURVEY_ALIAS, str3);
        intent.putExtra("url", str4);
        startActivity(intent);
    }

    public static String[] getSplitMessage(String str) {
        return str.split("\\|");
    }
}