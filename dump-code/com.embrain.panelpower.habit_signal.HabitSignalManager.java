package com.embrain.panelpower.habit_signal;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.provider.Settings.Secure;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalLibPrefs;
import co.habitfactory.signalfinance_embrain.comm.SignalUtil;
import com.embrain.panelbigdata.utils.StringUtils;
import com.embrain.panelpower.UserInfoManager;
import com.embrain.panelpower.UserInfoManager.UserInfo;
import com.embrain.panelpower.habit_signal.vo.SignalMappingVO;
import com.embrain.panelpower.networks.HttpManager;
import com.embrain.panelpower.networks.URLList;
import com.embrain.panelpower.utils.LogUtil;
import com.google.gson.Gson;
import java.io.IOException;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class HabitSignalManager {
    public static final int REQUEST_PERMISSION_REQUEST_PAY = 1008;
    private static final String TAG = "HabitSignalManager";
    /* access modifiers changed from: private */
    public static Context mContext;
    private static SignalIdReceive mIdReceive;
    private static SignalLibPrefs signalLibPrefs;

    public static void initSignalLib(Context context) {
        mContext = context;
        try {
            if (!checkPanelLogin()) {
                stopSignalLib(mContext);
            } else if (!checkPermission(mContext)) {
                stopSignalLib(mContext);
            } else {
                if (!checkRegist(mContext)) {
                    regist();
                } else {
                    checkSaveMode(mContext);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void stopSignalLib(Context context) {
        if (checkRegist(context)) {
            new SignalLibPrefs(context).setClearForSync(context);
        }
    }

    private static boolean checkPanelLogin() {
        return UserInfoManager.getInstance(mContext).getUserInfo() != null;
    }

    public static boolean checkPermission(Context context) {
        return hasNotificationAccess(context) && UserInfoManager.AGREE_Y.equals(UserInfoManager.getInstance(context).getUserInfo().getInfoPay());
    }

    private static boolean checkRegist(Context context) {
        return !StringUtils.isEmpty(UserInfoManager.getHabitUserId(context));
    }

    private static void regist() {
        signalLibPrefs = new SignalLibPrefs(mContext);
        mIdReceive = new SignalIdReceive();
        SignalMappingVO signalMappingVO = new SignalMappingVO();
        signalMappingVO.panelId = UserInfoManager.getInstance(mContext).getPanelId();
        signalMappingVO.userId = null;
        HttpManager.getInstance().requestHabitRegisted(signalMappingVO, new Callback() {
            public void onFailure(Call call, IOException iOException) {
                StringBuilder sb = new StringBuilder();
                sb.append("[requestHabitRegist] - onFailure : ");
                sb.append(iOException.getMessage());
                LogUtil.write(sb.toString());
            }

            public void onResponse(Call call, Response response) throws IOException {
                if (response.code() == 200) {
                    String str = (String) new Gson().fromJson(response.body().string(), String.class);
                    if (str.equals("NoUser")) {
                        HabitSignalManager.createSignalId(HabitSignalManager.mContext);
                    } else {
                        HabitSignalManager.signalLogin(HabitSignalManager.mContext, str);
                    }
                }
            }
        });
    }

    public static boolean hasNotificationAccess(Context context) {
        boolean z = false;
        try {
            String string = Secure.getString(context.getContentResolver(), "enabled_notification_listeners");
            StringBuilder sb = new StringBuilder();
            sb.append(context.getPackageName());
            sb.append("/");
            String sb2 = sb.toString();
            if (string != null && string.contains(sb2)) {
                z = true;
            }
            return z;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void setPayPermission(Activity activity) {
        activity.startActivityForResult(new Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"), 1008);
    }

    /* access modifiers changed from: private */
    public static void signalLogin(Context context, String str) {
        try {
            UserInfo userInfo = UserInfoManager.getInstance(context).getUserInfo();
            Context context2 = context;
            int signalLogin = signalLibPrefs.signalLogin(context2, URLList.SIGNAL_URL, str, userInfo.getBirthYear(), userInfo.getGender());
            StringBuilder sb = new StringBuilder();
            sb.append("habit signalLogin ======= ");
            sb.append(signalLogin);
            LogUtil.write(sb.toString());
            if (signalLogin == -1) {
                SignalUtil.PRINT_LOG(TAG, "\uc11c\ubc84URL \uc624\ub958");
            } else if (signalLogin == -3) {
                SignalUtil.PRINT_LOG(TAG, "\uc798\ubabb\ub41c signalId \uc785\ub2c8\ub2e4.");
            } else {
                LocalBroadcastManager.getInstance(context).registerReceiver(mIdReceive, new IntentFilter(SignalLibConsts.ACTION_SIGNALID_RECEIVE));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /* access modifiers changed from: private */
    public static void createSignalId(Context context) {
        try {
            UserInfo userInfo = UserInfoManager.getInstance(context).getUserInfo();
            int createSignalId = signalLibPrefs.createSignalId(context, URLList.SIGNAL_URL, userInfo.getBirthYear(), userInfo.getGender());
            StringBuilder sb = new StringBuilder();
            sb.append("habit createSignalId ======= ");
            sb.append(createSignalId);
            LogUtil.write(sb.toString());
            if (createSignalId == -1) {
                SignalUtil.PRINT_LOG(TAG, "\uc11c\ubc84URL \uc624\ub958");
            } else {
                LocalBroadcastManager.getInstance(context).registerReceiver(mIdReceive, new IntentFilter(SignalLibConsts.ACTION_SIGNALID_RECEIVE));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void checkSaveMode(Context context) {
        try {
            SignalLibPrefs signalLibPrefs2 = new SignalLibPrefs(context);
            if (signalLibPrefs2.setInitData(context, URLList.SIGNAL_URL, signalLibPrefs2.getString(SignalLibConsts.PREF_API_USER_USERID)) != -1) {
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void quitSignalLib(Context context) {
        signalLibPrefs = new SignalLibPrefs(context);
        signalLibPrefs.setQuitSignalData(context);
    }
}