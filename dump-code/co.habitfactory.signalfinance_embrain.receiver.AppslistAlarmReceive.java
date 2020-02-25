package co.habitfactory.signalfinance_embrain.receiver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalLibPrefs;
import co.habitfactory.signalfinance_embrain.comm.SignalUtil;
import co.habitfactory.signalfinance_embrain.jobservice.JGetUserApplicationListOnlyNewService;
import co.habitfactory.signalfinance_embrain.jobservice.JGetUserApplicationListService;

public class AppslistAlarmReceive extends BroadcastReceiver implements SignalLibConsts {
    private final String TAG = AppslistAlarmReceive.class.getSimpleName();

    public void onReceive(Context context, Intent intent) {
        String str;
        SignalUtil.PRINT_LOG(this.TAG, ": onReceive");
        SignalLibPrefs signalLibPrefs = new SignalLibPrefs(context);
        if (signalLibPrefs.getBoolean(SignalLibConsts.PREF_STOP_COLLECT, Boolean.valueOf(true)).booleanValue()) {
            SignalUtil.PRINT_LOG(this.TAG, ": \ud328\ud0a4\uc9c0\uba85 \ubb38\uc790 \uc218\uc9d1 \uc548\ud568.");
            return;
        }
        try {
            str = SignalUtil.getUserId(context);
        } catch (Exception e) {
            e.printStackTrace();
            str = "";
        }
        try {
            String str2 = this.TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("userId : ");
            sb.append(str);
            SignalUtil.PRINT_LOG(str2, sb.toString());
            if (str != null && str.length() > 0) {
                if (signalLibPrefs.getBoolean(SignalLibConsts.PREF_API_GOT_WHITEPACKAGE_FROM_API_CHECK, Boolean.valueOf(false)).booleanValue()) {
                    JGetUserApplicationListOnlyNewService.enqueueWork(context, new Intent(context, JGetUserApplicationListOnlyNewService.class));
                } else {
                    JGetUserApplicationListService.enqueueWork(context, new Intent(context, JGetUserApplicationListService.class));
                }
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }
}