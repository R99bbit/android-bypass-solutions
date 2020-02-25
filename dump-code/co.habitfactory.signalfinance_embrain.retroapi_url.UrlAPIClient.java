package co.habitfactory.signalfinance_embrain.retroapi_url;

import retrofit2.Call;
import retrofit2.http.GET;

public interface UrlAPIClient {
    @GET("client-setting.json")
    Call<Object> requestGetClientSetting();
}