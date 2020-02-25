package a.b.a.b;

import a.b.a.b.i.a;
import a.b.a.f;
import com.loplat.placeengine.PlengiResponse;
import com.loplat.placeengine.cloud.RequestMessage.RegisterUserReq;
import com.loplat.placeengine.cloud.ResponseMessage;
import com.loplat.placeengine.cloud.ResponseMessage.RegisterUserRes;
import retrofit2.Call;
import retrofit2.Response;

/* compiled from: CloudEndpoint */
public class e extends a<RegisterUserRes> {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ RegisterUserReq f9a;
    public final /* synthetic */ i b;

    /* JADX WARN: Illegal instructions before constructor call commented (this can break semantics) */
    public e(i iVar, RegisterUserReq registerUserReq) {
        // this.b = iVar;
        // this.f9a = registerUserReq;
        super(iVar);
    }

    public void onFailure(Call<RegisterUserRes> call, Throwable th) {
        this.b.a(th, this.f9a.getType());
        th.getLocalizedMessage();
    }

    public void onResponse(Call<RegisterUserRes> call, Response<RegisterUserRes> response) {
        RegisterUserRes registerUserRes = (RegisterUserRes) response.body();
        if (registerUserRes == null || !response.isSuccessful()) {
            f.a(i.f13a, this.f9a.getType(), response.errorBody().toString());
            return;
        }
        StringBuilder a2 = a.a.a.a.a.a("status:");
        a2.append(registerUserRes.getStatus());
        a2.append(", anid");
        a2.append(registerUserRes.getAnid());
        a2.toString();
        if (ResponseMessage.STATUS_FAIL.equals(registerUserRes.getStatus())) {
            f.a(i.f13a, (PlengiResponse) null, this.f9a.getType(), registerUserRes.getReason());
        }
        this.b.a(registerUserRes.getConfig(), true);
        this.b.a(registerUserRes.getAnid());
    }
}