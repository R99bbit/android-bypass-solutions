package a.b.a.b;

import a.b.a.b.i.a;
import a.b.a.f;
import com.loplat.placeengine.cloud.RequestMessage.LeavePlaceReq;
import com.loplat.placeengine.cloud.ResponseMessage.LeavePlaceRes;
import retrofit2.Call;
import retrofit2.Response;

/* compiled from: CloudEndpoint */
public class c extends a<LeavePlaceRes> {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ LeavePlaceReq f7a;
    public final /* synthetic */ i b;

    /* JADX WARN: Illegal instructions before constructor call commented (this can break semantics) */
    public c(i iVar, LeavePlaceReq leavePlaceReq) {
        // this.b = iVar;
        // this.f7a = leavePlaceReq;
        super(iVar);
    }

    public void onFailure(Call<LeavePlaceRes> call, Throwable th) {
        this.b.a(th, this.f7a.getType());
        th.getLocalizedMessage();
    }

    public void onResponse(Call<LeavePlaceRes> call, Response<LeavePlaceRes> response) {
        if (response.isSuccessful()) {
            LeavePlaceRes leavePlaceRes = (LeavePlaceRes) response.body();
            StringBuilder a2 = a.a.a.a.a.a("status:");
            a2.append(leavePlaceRes.getStatus());
            a2.append(", type");
            a2.append(leavePlaceRes.getType());
            a2.append(", reason");
            a2.append(leavePlaceRes.getReason());
            a2.toString();
            this.b.a(leavePlaceRes.getAnid());
            return;
        }
        f.a(i.f13a, this.f7a.getType(), response.errorBody().toString());
    }
}