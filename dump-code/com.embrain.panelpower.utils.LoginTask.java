package com.embrain.panelpower.utils;

import android.content.Context;
import android.os.AsyncTask;
import com.embrain.panelpower.UserInfoManager;
import com.embrain.panelpower.networks.PanelPowerInterceptor;
import com.embrain.panelpower.networks.vo.LoginVo;
import com.embrain.panelpower.networks.vo.ResponseLogin;
import com.google.gson.Gson;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request.Builder;
import okhttp3.RequestBody;

public class LoginTask extends AsyncTask<Void, Void, Void> {
    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    static final String LOGIN = "https://www.panel.co.kr/user/mobile/login/appLoginDesc";
    private Context mContext;

    public LoginTask(Context context) {
        this.mContext = context;
    }

    /* access modifiers changed from: protected */
    public Void doInBackground(Void... voidArr) {
        if (UserInfoManager.getInstance(this.mContext).getUserInfo() != null) {
            try {
                ((ResponseLogin) new Gson().fromJson(getClient().newCall(new Builder().url((String) LOGIN).post(RequestBody.create(JSON, LoginVo.getLoginInfo(this.mContext).toJson())).headers(getHeaders()).build()).execute().body().string(), ResponseLogin.class)).isSuccess();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    /* access modifiers changed from: protected */
    public void onPostExecute(Void voidR) {
        super.onPostExecute(voidR);
    }

    static Headers getHeaders() {
        return new Headers.Builder().add("Accept", "application/json, text/plain, */*").add("Content-Type", "application/json;charset=UTF-8").add("Referer", "https://www.panel.co.kr/mobile/native/AppAccess").build();
    }

    private static OkHttpClient getClient() {
        return getClient(15, 15);
    }

    private static OkHttpClient getClient(int i, int i2) {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.addInterceptor(new PanelPowerInterceptor());
        builder.connectTimeout((long) (i * 60 * 1000), TimeUnit.MILLISECONDS);
        builder.readTimeout((long) (i2 * 60 * 1000), TimeUnit.MILLISECONDS);
        return builder.build();
    }
}