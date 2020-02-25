package co.habitfactory.signalfinance_embrain.retroapi;

import co.habitfactory.signalfinance_embrain.comm.SignalUtil;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public abstract class RetryableCallback<T> implements Callback<T> {
    private static final String TAG = "RetryableCallback";
    private final Call<T> call;
    private int retryCount = 0;
    private int totalRetries = 3;

    public void onFinalFailure(Call<T> call2, Throwable th) {
    }

    public void onFinalResponse(Call<T> call2, Response<T> response) {
    }

    public RetryableCallback(Call<T> call2, int i) {
        this.call = call2;
        this.totalRetries = i;
    }

    public void onResponse(Call<T> call2, Response<T> response) {
        if (!APIHelper.isCallSuccess(response)) {
            int i = this.retryCount;
            this.retryCount = i + 1;
            if (i < this.totalRetries) {
                String str = TAG;
                StringBuilder sb = new StringBuilder();
                sb.append("Retrying API Call -  (");
                sb.append(this.retryCount);
                sb.append(" / ");
                sb.append(this.totalRetries);
                sb.append(")");
                SignalUtil.PRINT_LOG(str, sb.toString());
                retry();
                return;
            }
            onFinalResponse(call2, response);
            return;
        }
        onFinalResponse(call2, response);
    }

    public void onFailure(Call<T> call2, Throwable th) {
        SignalUtil.PRINT_LOG(TAG, th.getMessage());
        int i = this.retryCount;
        this.retryCount = i + 1;
        if (i < this.totalRetries) {
            String str = TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("Retrying API Call -  (");
            sb.append(this.retryCount);
            sb.append(" / ");
            sb.append(this.totalRetries);
            sb.append(")");
            SignalUtil.PRINT_LOG(str, sb.toString());
            retry();
            return;
        }
        onFinalFailure(call2, th);
    }

    private void retry() {
        this.call.clone().enqueue(this);
    }
}