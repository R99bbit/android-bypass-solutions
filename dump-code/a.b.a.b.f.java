package a.b.a.b;

import a.b.a.b.i.a;
import com.loplat.placeengine.PlengiResponse;
import com.loplat.placeengine.cloud.RequestMessage.UpdateSdkConfigReq;
import com.loplat.placeengine.cloud.ResponseMessage;
import com.loplat.placeengine.cloud.ResponseMessage.ConfigSdkEventRes;
import retrofit2.Call;
import retrofit2.Response;

/* compiled from: CloudEndpoint */
public class f extends a<ConfigSdkEventRes> {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ UpdateSdkConfigReq f10a;
    public final /* synthetic */ i b;

    /* JADX WARN: Illegal instructions before constructor call commented (this can break semantics) */
    public f(i iVar, UpdateSdkConfigReq updateSdkConfigReq) {
        // this.b = iVar;
        // this.f10a = updateSdkConfigReq;
        super(iVar);
    }

    public void onFailure(Call<ConfigSdkEventRes> call, Throwable th) {
        th.getLocalizedMessage();
    }

    public void onResponse(Call<ConfigSdkEventRes> call, Response<ConfigSdkEventRes> response) {
        ConfigSdkEventRes configSdkEventRes = (ConfigSdkEventRes) response.body();
        if (configSdkEventRes != null && response.isSuccessful()) {
            if (ResponseMessage.STATUS_FAIL.equals(configSdkEventRes.getStatus())) {
                a.b.a.f.a(i.f13a, (PlengiResponse) null, this.f10a.getType(), configSdkEventRes.getReason());
                return;
            }
            this.b.a(configSdkEventRes.getConfig(), false);
            this.b.a(configSdkEventRes.getAnid());
        }
    }
}