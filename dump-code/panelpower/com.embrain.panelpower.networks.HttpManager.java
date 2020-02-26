package com.embrain.panelpower.networks;

import com.embrain.panelpower.habit_signal.vo.SignalMappingVO;
import com.embrain.panelpower.networks.vo.AlarmListVo;
import com.embrain.panelpower.networks.vo.AppVersionVO;
import com.embrain.panelpower.networks.vo.EventRecommendMsgVO;
import com.embrain.panelpower.networks.vo.LoginVo;
import com.embrain.panelpower.networks.vo.MyInfoVo;
import com.embrain.panelpower.networks.vo.SurveyExpressVO;
import com.embrain.panelpower.utils.LogUtil;
import com.google.gson.Gson;
import java.util.concurrent.TimeUnit;
import okhttp3.Callback;
import okhttp3.Headers;
import okhttp3.OkHttpClient;
import okhttp3.OkHttpClient.Builder;

public class HttpManager {
    public static final int AGREE_CAll = 4;
    public static final int AGREE_EMAIL = 2;
    public static final int AGREE_LOCATION = 5;
    public static final int AGREE_MOBILE = 3;
    public static final int AGREE_PAY = 7;
    public static final int AGREE_PUSH = 1;
    public static final int AGREE_USAGE = 6;
    private static OkHttpClient mClient;
    private static HttpManager mInstance;

    public static HttpManager getInstance() {
        if (mInstance == null) {
            mInstance = new HttpManager();
        }
        return mInstance;
    }

    private HttpManager() {
        getClient();
    }

    private static OkHttpClient getClient() {
        return getClient(15, 15);
    }

    private static OkHttpClient getClient(int i, int i2) {
        if (mClient == null) {
            Builder builder = new Builder();
            builder.addInterceptor(new PanelPowerInterceptor());
            builder.connectTimeout((long) (i * 60 * 1000), TimeUnit.MILLISECONDS);
            builder.readTimeout((long) (i2 * 60 * 1000), TimeUnit.MILLISECONDS);
            mClient = builder.build();
        }
        return mClient;
    }

    static Headers getHeaders() {
        return new Headers.Builder().add("Accept", "application/json, text/plain, */*").add("Content-Type", "application/json;charset=UTF-8").add("Referer", "https://www.panel.co.kr/mobile/native/AppAccess").build();
    }

    public void requestVersionCheck(AppVersionVO appVersionVO, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("requestVersionCheck() : ");
        sb.append(new Gson().toJson((Object) appVersionVO));
        LogUtil.write(sb.toString());
        APIs.requestVersionCheck(getClient(), appVersionVO, callback);
    }

    public void requestLogin(LoginVo loginVo, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("requestLogin() : ");
        sb.append(new Gson().toJson((Object) loginVo));
        LogUtil.write(sb.toString());
        APIs.requestLogin(getClient(10, 10), loginVo, callback);
    }

    public void requestMyInfo(MyInfoVo myInfoVo, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("requestMyInfo() : ");
        sb.append(new Gson().toJson((Object) myInfoVo));
        LogUtil.write(sb.toString());
        APIs.requestMyInfo(getClient(), myInfoVo, callback);
    }

    public void requestSurveyExpress(SurveyExpressVO surveyExpressVO, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("requestSurveyExpress() : ");
        sb.append(new Gson().toJson((Object) surveyExpressVO));
        LogUtil.write(sb.toString());
        APIs.requestSurveyExpress(getClient(), surveyExpressVO, callback);
    }

    public void requestKakaoMsg(EventRecommendMsgVO eventRecommendMsgVO, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("requestKakaoMsg() : ");
        sb.append(new Gson().toJson((Object) eventRecommendMsgVO));
        LogUtil.write(sb.toString());
        APIs.requestKakaoMsg(getClient(), eventRecommendMsgVO, callback);
    }

    public void requestLineMsg(EventRecommendMsgVO eventRecommendMsgVO, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("requestLineMsg() : ");
        sb.append(new Gson().toJson((Object) eventRecommendMsgVO));
        LogUtil.write(sb.toString());
        APIs.requestLineMsg(getClient(), eventRecommendMsgVO, callback);
    }

    public void requestHabitRegisted(SignalMappingVO signalMappingVO, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("requestHabitRegisted() : ");
        sb.append(new Gson().toJson((Object) signalMappingVO));
        LogUtil.write(sb.toString());
        APIs.requestHabitRegisted(getClient(), signalMappingVO, callback);
    }

    public void requestHabitMapping(SignalMappingVO signalMappingVO, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("requestHabitMapping() : ");
        sb.append(new Gson().toJson((Object) signalMappingVO));
        LogUtil.write(sb.toString());
        APIs.requestHabitMapping(getClient(), signalMappingVO, callback);
    }

    public void requestAlarmList(AlarmListVo alarmListVo, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("requestAlarmList() : ");
        sb.append(new Gson().toJson((Object) alarmListVo));
        LogUtil.write(sb.toString());
        APIs.requestAlarmList(getClient(), alarmListVo, callback);
    }

    public void requestAgree(int i, String str, Callback callback) {
        String str2;
        switch (i) {
            case 1:
                str2 = URLList.AGREE_PUSH;
                break;
            case 2:
                str2 = URLList.AGREE_EMAIL;
                break;
            case 3:
                str2 = URLList.AGREE_MOBILE;
                break;
            case 4:
                str2 = URLList.AGREE_CALL;
                break;
            case 5:
                str2 = URLList.AGREE_LOCATION;
                break;
            case 6:
                str2 = URLList.AGREE_USAGE;
                break;
            case 7:
                str2 = URLList.AGREE_PAY;
                break;
            default:
                str2 = "";
                break;
        }
        APIs.requestAgree(getClient(10, 10), str2, str, callback);
    }
}