package a.b.a.b;

import a.b.a.f;
import a.b.a.g;
import android.content.Context;
import android.os.SystemClock;
import com.loplat.placeengine.OnPlengiListener;
import com.loplat.placeengine.PlaceEngineBase;
import com.loplat.placeengine.PlengiResponse;
import com.loplat.placeengine.PlengiResponse.Location;
import com.loplat.placeengine.cloud.RequestMessage;
import com.loplat.placeengine.cloud.RequestMessage.SearchPlaceReq;
import com.loplat.placeengine.cloud.RequestMessage.Specialty;
import com.loplat.placeengine.cloud.ResponseMessage.SearchPlaceRes;
import retrofit2.Call;
import retrofit2.Response;

/* compiled from: CloudEndpoint */
class a extends a.b.a.b.i.a<SearchPlaceRes> {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ SearchPlaceReq f5a;
    public final /* synthetic */ OnPlengiListener b;
    public final /* synthetic */ PlengiResponse c;
    public final /* synthetic */ i d;

    /* JADX WARN: Illegal instructions before constructor call commented (this can break semantics) */
    public a(i iVar, SearchPlaceReq searchPlaceReq, OnPlengiListener onPlengiListener, PlengiResponse plengiResponse) {
        // this.d = iVar;
        // this.f5a = searchPlaceReq;
        // this.b = onPlengiListener;
        // this.c = plengiResponse;
        super(iVar);
    }

    public void onFailure(Call<SearchPlaceRes> call, Throwable th) {
        try {
            String type = this.f5a.getType();
            a.b.a.c.a.b(i.f13a).b();
            int h = a.b.a.g.a.h(i.f13a);
            if (h == 0) {
                f.a(i.f13a, 0);
            } else if (h == 1) {
                g.c(i.f13a, 0);
            }
            PlengiResponse a2 = f.a(i.f13a, th, type);
            if (this.b != null) {
                this.b.onFail(a2);
            }
            if (!RequestMessage.SEARCH_PLACE.equals(type)) {
                return;
            }
            if (a.b.a.g.a.o(i.f13a)) {
                Specialty specialtyRequest = PlaceEngineBase.getSpecialtyRequest(i.f13a);
                if (specialtyRequest != null) {
                    super.a(this.f5a, specialtyRequest);
                } else {
                    th.getLocalizedMessage();
                }
            } else {
                th.getLocalizedMessage();
            }
        } catch (Exception unused) {
        }
    }

    public void onResponse(Call<SearchPlaceRes> call, Response<SearchPlaceRes> response) {
        Context context = i.f13a;
        String type = this.f5a.getType();
        if (response.isSuccessful()) {
            SearchPlaceRes searchPlaceRes = (SearchPlaceRes) response.body();
            searchPlaceRes.setType(type);
            this.d.a(searchPlaceRes, this.c, this.b);
            if (searchPlaceRes.getLocation() == null) {
                Location location = this.c.location;
                if (location != null) {
                    searchPlaceRes.setLocation(location);
                }
            }
            a.b.a.c.a.b(context).b(SystemClock.elapsedRealtime());
            if (this.c.location != null) {
                a.b.a.c.a.b(context).a(this.c.location.getLat(), this.c.location.getLng());
            } else {
                a.b.a.c.a.b(context).d();
            }
            l.a(context, this.c);
            return;
        }
        int code = response.code();
        String obj = response.errorBody().toString();
        if (code >= 400 && code < 500) {
            PlaceEngineBase.saveAdUrl(context, null);
            PlaceEngineBase.savePlaceUrl(context, null);
            if (l.a(l.j)) {
                l.d = null;
                l.e = null;
                l.a(1);
            } else {
                l.b = null;
                l.c = null;
                l.a(0);
            }
        }
        StringBuilder sb = new StringBuilder();
        sb.append(code);
        sb.append(":");
        sb.append(obj);
        f.a(context, type, sb.toString());
        if (PlengiResponse.LOCATION_ACQUISITION_FAIL.equals(obj)) {
            l.a(context, this.c);
        }
    }
}