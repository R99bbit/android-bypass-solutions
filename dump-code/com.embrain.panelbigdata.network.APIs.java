package com.embrain.panelbigdata.network;

import com.embrain.panelbigdata.Vo.location.LocationGpsListRequest;
import com.embrain.panelbigdata.Vo.location.LocationGpsRequest;
import com.embrain.panelbigdata.Vo.location.LocationInsertRequest;
import com.embrain.panelbigdata.Vo.push.BigdataSessionListRequest;
import com.embrain.panelbigdata.Vo.push.BigdataSessionRequest;
import com.embrain.panelbigdata.Vo.token.RegistTokenRequest;
import com.embrain.panelbigdata.Vo.usage.UsageInsertRequest;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request.Builder;
import okhttp3.RequestBody;

class APIs {
    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

    APIs() {
    }

    static void sendBigdataSession(OkHttpClient okHttpClient, BigdataSessionRequest bigdataSessionRequest, Callback callback) {
        okHttpClient.newCall(new Builder().url(URLList.BIG_DATA_SESSION).post(RequestBody.create(JSON, bigdataSessionRequest.toJson())).headers(HttpManager.getHeaders()).build()).enqueue(callback);
    }

    static void sendBigdataSessionList(OkHttpClient okHttpClient, BigdataSessionListRequest bigdataSessionListRequest, Callback callback) {
        okHttpClient.newCall(new Builder().url(URLList.BIG_DATA_SESSION_LISt).post(RequestBody.create(JSON, bigdataSessionListRequest.toJson())).headers(HttpManager.getHeaders()).build()).enqueue(callback);
    }

    static void sendUsageInfo(OkHttpClient okHttpClient, UsageInsertRequest usageInsertRequest, Callback callback) {
        okHttpClient.newCall(new Builder().url(URLList.USAGE_INFO).post(RequestBody.create(JSON, usageInsertRequest.toJson())).headers(HttpManager.getHeaders()).build()).enqueue(callback);
    }

    static void sendLoacationInfo(OkHttpClient okHttpClient, LocationInsertRequest locationInsertRequest, Callback callback) {
        okHttpClient.newCall(new Builder().url(URLList.LOCATION_INFO).post(RequestBody.create(JSON, locationInsertRequest.toJson())).headers(HttpManager.getHeaders()).build()).enqueue(callback);
    }

    static void sendToken(OkHttpClient okHttpClient, RegistTokenRequest registTokenRequest, Callback callback) {
        okHttpClient.newCall(new Builder().url(URLList.TOKEN_REGIST).post(RequestBody.create(JSON, registTokenRequest.toJson())).headers(HttpManager.getHeaders()).build()).enqueue(callback);
    }

    static void sendGpsState(OkHttpClient okHttpClient, LocationGpsRequest locationGpsRequest, Callback callback) {
        okHttpClient.newCall(new Builder().url(URLList.GPS_STATE).post(RequestBody.create(JSON, locationGpsRequest.toJson())).headers(HttpManager.getHeaders()).build()).enqueue(callback);
    }

    static void sendGpsStateList(OkHttpClient okHttpClient, LocationGpsListRequest locationGpsListRequest, Callback callback) {
        okHttpClient.newCall(new Builder().url(URLList.GPS_STATE_LIST).post(RequestBody.create(JSON, locationGpsListRequest.toJson())).headers(HttpManager.getHeaders()).build()).enqueue(callback);
    }
}