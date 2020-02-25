package co.habitfactory.signalfinance_embrain.retroapi;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class APIHelper {
    public static final int DEFAULT_RETRIES = 3;

    public static <T> void enqueueWithRetry(Call<T> call, int i, final Callback<T> callback) {
        call.enqueue(new RetryableCallback<T>(call, i) {
            public void onFinalResponse(Call<T> call, Response<T> response) {
                callback.onResponse(call, response);
            }

            public void onFinalFailure(Call<T> call, Throwable th) {
                callback.onFailure(call, th);
            }
        });
    }

    public static <T> void enqueueWithRetry(Call<T> call, Callback<T> callback) {
        enqueueWithRetry(call, 3, callback);
    }

    public static boolean isCallSuccess(Response response) {
        int code = response.code();
        return code >= 200 && code < 400;
    }
}