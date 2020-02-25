package a.b.a.b;

import a.b.a.b.i.a;
import a.b.a.f;
import com.loplat.placeengine.cloud.RequestMessage.ReportPlaceEngineStatus;
import com.loplat.placeengine.cloud.ResponseMessage.ReportPlaceEngState;
import retrofit2.Call;
import retrofit2.Response;

/* compiled from: CloudEndpoint */
public class d extends a<ReportPlaceEngState> {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ ReportPlaceEngineStatus f8a;
    public final /* synthetic */ i b;

    /* JADX WARN: Illegal instructions before constructor call commented (this can break semantics) */
    public d(i iVar, ReportPlaceEngineStatus reportPlaceEngineStatus) {
        // this.b = iVar;
        // this.f8a = reportPlaceEngineStatus;
        super(iVar);
    }

    public void onFailure(Call<ReportPlaceEngState> call, Throwable th) {
        this.b.a(th, this.f8a.getType());
        th.getLocalizedMessage();
    }

    public void onResponse(Call<ReportPlaceEngState> call, Response<ReportPlaceEngState> response) {
        if (response.isSuccessful()) {
            ReportPlaceEngState reportPlaceEngState = (ReportPlaceEngState) response.body();
            StringBuilder a2 = a.a.a.a.a.a("status:");
            a2.append(reportPlaceEngState.getStatus());
            a2.append(", type:");
            a2.append(reportPlaceEngState.getType());
            a2.toString();
            this.b.a(reportPlaceEngState.getConfig(), false);
            this.b.a(reportPlaceEngState.getAnid());
            return;
        }
        f.a(i.f13a, this.f8a.getType(), response.errorBody().toString());
    }
}