package com.embrain.panelbigdata.location;

import android.content.Context;
import com.embrain.panelbigdata.EmBigDataManager;
import com.embrain.panelbigdata.EmBigdataApplication;
import com.embrain.panelbigdata.network.HttpManager;
import com.embrain.panelbigdata.utils.LogUtil;
import com.embrain.panelbigdata.utils.PrefUtils;
import com.google.gson.Gson;
import com.loplat.placeengine.PlengiListener;
import com.loplat.placeengine.PlengiResponse;
import java.io.IOException;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class EmbrainPlengiListener implements PlengiListener {
    private static String TAG = "[Loplat]";
    private Context mContext = EmBigDataManager.getContext();

    public void listen(PlengiResponse plengiResponse) {
        StringBuilder sb = new StringBuilder();
        sb.append("[LoplatPlengiListener]=============PlengiResponse_response>>>>>>>");
        sb.append(plengiResponse.result);
        LogUtil.write(sb.toString());
        StringBuilder sb2 = new StringBuilder();
        sb2.append("resposnse : ");
        sb2.append(new Gson().toJson((Object) plengiResponse));
        LogUtil.write(sb2.toString());
        if (EmBigdataApplication.getContext() == null) {
            LogUtil.write("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            LogUtil.write("EmbrainPlengiListener not has context !!!!!!!!!!!!!!!!!!!!!!!!!!! NULL!!!!!!!!!!!!!!!!!!!!!!!!!!");
            LogUtil.write("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            return;
        }
        LocationInsertRequestExt locationInsertRequestExt = new LocationInsertRequestExt(PrefUtils.getPanelId(this.mContext), PrefUtils.getGoogleADID(this.mContext));
        locationInsertRequestExt.setLoplatObj(plengiResponse);
        HttpManager.getInstance().sendLocationInfo(locationInsertRequestExt, new Callback() {
            public void onFailure(Call call, IOException iOException) {
                StringBuilder sb = new StringBuilder();
                sb.append("sendLocationInfo.onFailure : ");
                sb.append(iOException.getMessage());
                LogUtil.write(sb.toString());
            }

            public void onResponse(Call call, Response response) throws IOException {
                try {
                    StringBuilder sb = new StringBuilder();
                    sb.append("sendLocationInfo.onResponse : ");
                    sb.append(response.body().string());
                    LogUtil.write(sb.toString());
                } catch (Exception e) {
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("sendLocationInfo.onResponse : ");
                    sb2.append(e.getMessage());
                    LogUtil.write(sb2.toString());
                }
            }
        });
    }
}