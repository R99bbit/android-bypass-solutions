package com.embrain.panelpower.habit_signal;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import co.habitfactory.signalfinance_embrain.comm.ResultCode;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalLibPrefs;
import com.embrain.panelpower.UserInfoManager;
import com.embrain.panelpower.habit_signal.vo.SignalMappingVO;
import com.embrain.panelpower.networks.HttpManager;
import com.embrain.panelpower.networks.URLList;
import com.embrain.panelpower.utils.LogUtil;
import com.google.gson.Gson;
import java.io.IOException;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class SignalIdReceive extends BroadcastReceiver implements SignalLibConsts {
    private static final String ALREADY_REGITED = "\uc774\ubbf8 \ub4f1\ub85d\ub41c \uc720\uc800\uc758 \uc544\uc774\ub514\uac00 \ud3ec\ud568\ub418\uc5b4\uc788\uc2b5\ub2c8\ub2e4.";
    public static final int SYNC_TERM = 365;

    public void onReceive(Context context, Intent intent) {
        LocalBroadcastManager.getInstance(context).unregisterReceiver(this);
        String str = null;
        try {
            str = intent.getStringExtra("signalId");
            StringBuilder sb = new StringBuilder();
            sb.append("signalId : ");
            sb.append(str);
            LogUtil.write(sb.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (str != null && !ResultCode.CODE_m9999.equals(str)) {
            initSignal(context, str);
        }
    }

    private void initSignal(Context context, String str) {
        SignalLibPrefs signalLibPrefs = new SignalLibPrefs(context);
        signalLibPrefs.putString(SignalLibConsts.PREF_API_USER_USERID, str);
        if (signalLibPrefs.setInitData(context, URLList.SIGNAL_URL, str, 1) == -1) {
            LogUtil.write("\uc720\uc800 \uc544\uc774\ub514 \uc5c6\uc74c");
        } else {
            registHabitID(context, str);
        }
    }

    private void registHabitID(final Context context, final String str) {
        SignalMappingVO signalMappingVO = new SignalMappingVO();
        signalMappingVO.panelId = UserInfoManager.getInstance(context).getPanelId();
        signalMappingVO.userId = str;
        HttpManager.getInstance().requestHabitMapping(signalMappingVO, new Callback() {
            public void onFailure(Call call, IOException iOException) {
                StringBuilder sb = new StringBuilder();
                sb.append("[requestHabitMapping] - onFailure : ");
                sb.append(iOException.getMessage());
                LogUtil.write(sb.toString());
            }

            public void onResponse(Call call, Response response) throws IOException {
                LogUtil.write("[requestHabitMapping] - onResponse ");
                if (response.code() == 200) {
                    String str = (String) new Gson().fromJson(response.body().string(), String.class);
                    if ("Success".equals(str) || SignalIdReceive.ALREADY_REGITED.equals(str)) {
                        UserInfoManager.setHabitUserId(context, str);
                    }
                }
            }
        });
    }
}