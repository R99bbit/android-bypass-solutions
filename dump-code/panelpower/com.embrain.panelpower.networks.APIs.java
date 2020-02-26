package com.embrain.panelpower.networks;

import com.embrain.panelpower.habit_signal.vo.SignalMappingVO;
import com.embrain.panelpower.networks.vo.AlarmListVo;
import com.embrain.panelpower.networks.vo.AppVersionVO;
import com.embrain.panelpower.networks.vo.EventRecommendMsgVO;
import com.embrain.panelpower.networks.vo.LoginVo;
import com.embrain.panelpower.networks.vo.MyInfoVo;
import com.embrain.panelpower.networks.vo.SurveyExpressVO;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request.Builder;
import okhttp3.RequestBody;

class APIs {
    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

    APIs() {
    }

    private static synchronized void request(OkHttpClient okHttpClient, String str, String str2, Callback callback) {
        synchronized (APIs.class) {
            okHttpClient.newCall(new Builder().url(str).post(RequestBody.create(JSON, str2)).headers(HttpManager.getHeaders()).build()).enqueue(callback);
        }
    }

    static void requestVersionCheck(OkHttpClient okHttpClient, AppVersionVO appVersionVO, Callback callback) {
        request(okHttpClient, URLList.VERSION_CHECK, appVersionVO.toJson(), callback);
    }

    static void requestLogin(OkHttpClient okHttpClient, LoginVo loginVo, Callback callback) {
        request(okHttpClient, "https://www.panel.co.kr/mobile/login/appLoginDesc", loginVo.toJson(), callback);
    }

    static void requestMyInfo(OkHttpClient okHttpClient, MyInfoVo myInfoVo, Callback callback) {
        request(okHttpClient, URLList.MY_INFO, myInfoVo.toJson(), callback);
    }

    static void requestSurveyExpress(OkHttpClient okHttpClient, SurveyExpressVO surveyExpressVO, Callback callback) {
        request(okHttpClient, URLList.SURVEY_EXPRESS, surveyExpressVO.toJson(), callback);
    }

    static void requestKakaoMsg(OkHttpClient okHttpClient, EventRecommendMsgVO eventRecommendMsgVO, Callback callback) {
        request(okHttpClient, URLList.EVENT_RECOMMEND_KAKAO_MSG, eventRecommendMsgVO.toJson(), callback);
    }

    static void requestLineMsg(OkHttpClient okHttpClient, EventRecommendMsgVO eventRecommendMsgVO, Callback callback) {
        request(okHttpClient, URLList.EVENT_RECOMMEND_LINE_MSG, eventRecommendMsgVO.toJson(), callback);
    }

    static void requestHabitRegisted(OkHttpClient okHttpClient, SignalMappingVO signalMappingVO, Callback callback) {
        request(okHttpClient, URLList.REGISTED_HABIT, signalMappingVO.toJson(), callback);
    }

    static void requestHabitMapping(OkHttpClient okHttpClient, SignalMappingVO signalMappingVO, Callback callback) {
        request(okHttpClient, URLList.ID_MAPPING_HABIT, signalMappingVO.toJson(), callback);
    }

    static void requestAlarmList(OkHttpClient okHttpClient, AlarmListVo alarmListVo, Callback callback) {
        request(okHttpClient, URLList.ALARM_LIST, alarmListVo.toJson(), callback);
    }

    static void requestAgree(OkHttpClient okHttpClient, String str, String str2, Callback callback) {
        request(okHttpClient, str, str2, callback);
    }
}