package a.b.a.b;

import a.b.a.b.i.a;
import a.b.a.f;
import android.content.Context;
import com.loplat.placeengine.OnPlengiListener;
import com.loplat.placeengine.PlengiResponse;
import com.loplat.placeengine.cloud.RequestMessage.SearchPlaceReq;
import com.loplat.placeengine.cloud.ResponseMessage.SearchPlaceRes;
import retrofit2.Call;
import retrofit2.Response;

/* compiled from: CloudEndpoint */
public class b extends a<SearchPlaceRes> {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ OnPlengiListener f6a;
    public final /* synthetic */ PlengiResponse b;
    public final /* synthetic */ SearchPlaceReq c;
    public final /* synthetic */ i d;

    /* JADX WARN: Illegal instructions before constructor call commented (this can break semantics) */
    public b(i iVar, OnPlengiListener onPlengiListener, PlengiResponse plengiResponse, SearchPlaceReq searchPlaceReq) {
        // this.d = iVar;
        // this.f6a = onPlengiListener;
        // this.b = plengiResponse;
        // this.c = searchPlaceReq;
        super(iVar);
    }

    public void onFailure(Call<SearchPlaceRes> call, Throwable th) {
        OnPlengiListener onPlengiListener = this.f6a;
        if (onPlengiListener != null) {
            PlengiResponse plengiResponse = this.b;
            plengiResponse.result = -3;
            plengiResponse.errorReason = PlengiResponse.NETWORK_FAIL;
            onPlengiListener.onFail(plengiResponse);
        }
    }

    public void onResponse(Call<SearchPlaceRes> call, Response<SearchPlaceRes> response) {
        Context context = i.f13a;
        String type = this.c.getType();
        if (response.isSuccessful()) {
            SearchPlaceRes searchPlaceRes = (SearchPlaceRes) response.body();
            if ("success".equals(searchPlaceRes.getStatus())) {
                PlengiResponse plengiResponse = this.b;
                plengiResponse.result = 0;
                plengiResponse.place = searchPlaceRes.getPlace();
                this.b.area = searchPlaceRes.getArea();
                this.b.district = searchPlaceRes.getDistrict();
                this.b.complex = searchPlaceRes.getComplex();
                this.b.nearbys = searchPlaceRes.getNearbys();
                this.b.geoFence = searchPlaceRes.getGeoFence();
                OnPlengiListener onPlengiListener = this.f6a;
                if (onPlengiListener != null) {
                    onPlengiListener.onSuccess(this.b);
                }
            } else if (this.f6a != null) {
                PlengiResponse plengiResponse2 = this.b;
                plengiResponse2.result = -1;
                plengiResponse2.errorReason = searchPlaceRes.getReason();
                this.f6a.onFail(this.b);
            } else {
                f.a(context, this.b, type, (String) PlengiResponse.LOCATION_ACQUISITION_FAIL);
            }
            this.d.a(searchPlaceRes.getConfig(), false);
            this.d.a(searchPlaceRes.getAnid());
        } else if (this.f6a != null) {
            PlengiResponse plengiResponse3 = this.b;
            plengiResponse3.result = -4;
            StringBuilder sb = new StringBuilder();
            sb.append(response.code());
            sb.append(":");
            sb.append(response.message());
            plengiResponse3.errorReason = sb.toString();
            this.f6a.onFail(this.b);
        }
    }
}