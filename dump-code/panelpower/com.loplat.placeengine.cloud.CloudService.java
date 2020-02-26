package com.loplat.placeengine.cloud;

import com.loplat.placeengine.cloud.RequestMessage.LeavePlaceReq;
import com.loplat.placeengine.cloud.RequestMessage.RegisterUserReq;
import com.loplat.placeengine.cloud.RequestMessage.ReportPlaceEngineStatus;
import com.loplat.placeengine.cloud.RequestMessage.SearchPlaceReq;
import com.loplat.placeengine.cloud.RequestMessage.SendAdResultReq;
import com.loplat.placeengine.cloud.RequestMessage.UpdateSdkConfigReq;
import com.loplat.placeengine.cloud.RequestMessage.UplusLbmsReq;
import com.loplat.placeengine.cloud.ResponseMessage.ConfigSdkEventRes;
import com.loplat.placeengine.cloud.ResponseMessage.LeavePlaceRes;
import com.loplat.placeengine.cloud.ResponseMessage.RegisterUserRes;
import com.loplat.placeengine.cloud.ResponseMessage.ReportPlaceEngState;
import com.loplat.placeengine.cloud.ResponseMessage.SearchPlaceRes;
import com.loplat.placeengine.cloud.ResponseMessage.UplusLbmsRes;
import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.POST;

public interface CloudService {
    @POST("sdk_event")
    Call<ConfigSdkEventRes> postConfigSdkEvent(@Body UpdateSdkConfigReq updateSdkConfigReq);

    @POST("ad/track")
    Call<Void> postFeedbackAdResult(@Body SendAdResultReq sendAdResultReq);

    @POST("placeevent")
    Call<LeavePlaceRes> postLeavePlace(@Body LeavePlaceReq leavePlaceReq);

    @POST("sdk_event")
    Call<ReportPlaceEngState> postPlaceEngineStatus(@Body ReportPlaceEngineStatus reportPlaceEngineStatus);

    @POST("sdk_event")
    Call<RegisterUserRes> postRegisterUser(@Body RegisterUserReq registerUserReq);

    @POST("searchplace")
    Call<SearchPlaceRes> postSearchPlace(@Body SearchPlaceReq searchPlaceReq);

    @POST("lbms/reqCellLatNLngInfo.do")
    Call<UplusLbmsRes> postUplusLBMS(@Body UplusLbmsReq uplusLbmsReq);
}