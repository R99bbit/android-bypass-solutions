package a.b.a.b;

import a.b.a.b.i.a;
import retrofit2.Call;
import retrofit2.Response;

/* compiled from: CloudEndpoint */
public class g extends a<Void> {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ String f11a;

    /* JADX WARN: Illegal instructions before constructor call commented (this can break semantics) */
    public g(i iVar, String str) {
        // this.f11a = str;
        super(iVar);
    }

    public void onFailure(Call<Void> call, Throwable th) {
        StringBuilder a2 = a.a.a.a.a.a("network error! ");
        a2.append(this.f11a);
        a2.toString();
        th.getLocalizedMessage();
    }

    public void onResponse(Call<Void> call, Response<Void> response) {
        if (response.isSuccessful()) {
            String str = this.f11a;
            return;
        }
        StringBuilder a2 = a.a.a.a.a.a("error! ");
        a2.append(this.f11a);
        a2.toString();
    }
}