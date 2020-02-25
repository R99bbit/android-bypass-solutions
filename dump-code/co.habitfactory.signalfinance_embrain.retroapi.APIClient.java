package co.habitfactory.signalfinance_embrain.retroapi;

import co.habitfactory.signalfinance_embrain.retroapi.request.IptAdid;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptCommon;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptSaveBundlePushData;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptServerTime;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptSignUp;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptUpdateLocation;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptUserAppFilteredList;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptYearGender;
import co.habitfactory.signalfinance_embrain.retroapi.request.sms.IptSavePushData;
import co.habitfactory.signalfinance_embrain.retroapi.request.user.IptUserAppList;
import co.habitfactory.signalfinance_embrain.retroapi.response.OptResultDataset;
import co.habitfactory.signalfinance_embrain.retroapi.response.OptServerTime;
import co.habitfactory.signalfinance_embrain.retroapi.response.OptSmsNumber;
import co.habitfactory.signalfinance_embrain.retroapi.response.ResponseResult;
import co.habitfactory.signalfinance_embrain.retroapi.response.layout.comm.OptPushPackageNameList;
import co.habitfactory.signalfinance_embrain.retroapi.response.layout.member.OptSignUp;
import co.habitfactory.signalfinance_embrain.retroapi.response.layout.sms.OptSaveSmsData;
import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.POST;

public interface APIClient {
    @POST("partner/embrain/profileUpdateForPartner.do")
    Call<ResponseResult> profileUpdateForPartner(@Body IptYearGender iptYearGender);

    @POST("partner/embrain/getSmsNumberList.do")
    Call<OptSmsNumber> requestGetSmsNumberList(@Body IptCommon iptCommon);

    @POST("partner/embrain/getSmsNumberListOnlyNew.do")
    Call<OptSmsNumber> requestGetSmsNumberListOnlyNew(@Body IptCommon iptCommon);

    @POST("partner/embrain/saveBundlePushData.do")
    Call<OptResultDataset> requestSaveBundlePushData(@Body IptSaveBundlePushData iptSaveBundlePushData);

    @POST("partner/embrain/saveBundleMessage.do")
    Call<OptResultDataset> requestSaveBundlePushSmsData(@Body IptSaveBundlePushData iptSaveBundlePushData);

    @POST("partner/embrain/savePushData.do")
    Call<OptSaveSmsData> requestSavePushData(@Body IptSavePushData iptSavePushData);

    @POST("partner/embrain/saveMessage.do")
    Call<OptSaveSmsData> requestSavePushSmsData(@Body IptSavePushData iptSavePushData);

    @POST("partner/embrain/saveUserApp.do")
    Call<ResponseResult> requestSaveUserApp(@Body IptUserAppList iptUserAppList);

    @POST("partner/embrain/saveUserAppFiltered.do")
    Call<ResponseResult> requestSaveUserAppFiltered(@Body IptUserAppFilteredList iptUserAppFilteredList);

    @POST("partner/embrain/getServerDateTime.do")
    Call<OptServerTime> requestServerDateTime(@Body IptServerTime iptServerTime);

    @POST("partner/embrain/updatePushLocation.do")
    Call<ResponseResult> requestUpdatePushLocation(@Body IptUpdateLocation iptUpdateLocation);

    @POST("partner/embrain/updateSmsLocation.do")
    Call<OptResultDataset> requestUpdateSmsLocation(@Body IptUpdateLocation iptUpdateLocation);

    @POST("partner/embrain/retrievePushPackageName.do")
    Call<OptPushPackageNameList> retrievePushPackageName(@Body IptCommon iptCommon);

    @POST("partner/embrain/retrievePushPackageNameOnlyNew.do")
    Call<OptPushPackageNameList> retrievePushPackageNameOnlyNew(@Body IptCommon iptCommon);

    @POST("partner/embrain/signUpForPartner.do")
    Call<OptSignUp> signUpForPartner(@Body IptSignUp iptSignUp);

    @POST("partner/embrain/updateAdid.do")
    Call<OptResultDataset> updateAdid(@Body IptAdid iptAdid);
}