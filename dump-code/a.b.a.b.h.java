package a.b.a.b;

import a.b.a.b.i.a;
import a.b.a.d.c.C0000c;
import com.loplat.placeengine.cloud.ResponseMessage.UplusLbmsRes;
import retrofit2.Call;
import retrofit2.Response;

/* compiled from: CloudEndpoint */
public class h extends a<UplusLbmsRes> {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ C0000c f12a;

    /* JADX WARN: Illegal instructions before constructor call commented (this can break semantics) */
    public h(i iVar, C0000c cVar) {
        // this.f12a = cVar;
        super(iVar);
    }

    public void onFailure(Call<UplusLbmsRes> call, Throwable th) {
        th.getLocalizedMessage();
        C0000c cVar = this.f12a;
        if (cVar != null) {
            ((a.b.a.d.a) cVar).a((String) "network error");
        }
    }

    public void onResponse(Call<UplusLbmsRes> call, Response<UplusLbmsRes> response) {
        UplusLbmsRes uplusLbmsRes = (UplusLbmsRes) response.body();
        if (uplusLbmsRes == null || !response.isSuccessful()) {
            StringBuilder a2 = a.a.a.a.a.a("lbs fail:");
            a2.append(response.code());
            ((a.b.a.d.a) this.f12a).a(a2.toString());
        } else if ("0000".equals(uplusLbmsRes.getResult_code())) {
            ((a.b.a.d.a) this.f12a).a(uplusLbmsRes);
        } else {
            StringBuilder a3 = a.a.a.a.a.a("lbs fail:");
            a3.append(uplusLbmsRes.getResult_code());
            ((a.b.a.d.a) this.f12a).a(a3.toString());
        }
    }
}