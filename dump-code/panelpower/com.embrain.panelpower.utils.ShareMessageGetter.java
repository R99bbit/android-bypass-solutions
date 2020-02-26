package com.embrain.panelpower.utils;

import android.os.AsyncTask;
import com.embrain.panelbigdata.utils.StringUtils;
import com.embrain.panelpower.UserInfoManager;
import com.embrain.panelpower.networks.HttpManager;
import com.embrain.panelpower.networks.vo.EventRecommendMsgVO;
import com.embrain.panelpower.networks.vo.ResponseRecommandMessage;
import com.google.gson.Gson;
import java.io.IOException;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class ShareMessageGetter extends AsyncTask<String, Void, Void> {
    /* access modifiers changed from: protected */
    public Void doInBackground(String... strArr) {
        String str = strArr[0];
        String str2 = strArr[1];
        if (!StringUtils.isEmpty(str) && !StringUtils.isEmpty(str2)) {
            EventRecommendMsgVO eventRecommendMsgVO = new EventRecommendMsgVO(str, str2);
            HttpManager.getInstance().requestKakaoMsg(eventRecommendMsgVO, new Callback() {
                public void onFailure(Call call, IOException iOException) {
                }

                public void onResponse(Call call, Response response) throws IOException {
                    try {
                        ResponseRecommandMessage responseRecommandMessage = (ResponseRecommandMessage) new Gson().fromJson(response.body().string(), ResponseRecommandMessage.class);
                        if (responseRecommandMessage.isSuccess()) {
                            UserInfoManager.mKakaoMsg = responseRecommandMessage.kakaoMsg;
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });
            HttpManager.getInstance().requestLineMsg(eventRecommendMsgVO, new Callback() {
                public void onFailure(Call call, IOException iOException) {
                }

                public void onResponse(Call call, Response response) throws IOException {
                    try {
                        ResponseRecommandMessage responseRecommandMessage = (ResponseRecommandMessage) new Gson().fromJson(response.body().string(), ResponseRecommandMessage.class);
                        if (responseRecommandMessage.isSuccess()) {
                            UserInfoManager.mLineMsg = responseRecommandMessage.lineMsg;
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });
        }
        return null;
    }
}