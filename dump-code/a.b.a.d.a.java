package a.b.a.d;

import a.b.a.d.c.C0000c;
import com.loplat.placeengine.OnPlengiListener;
import com.loplat.placeengine.cloud.RequestMessage.Location;
import com.loplat.placeengine.cloud.ResponseMessage.UplusLbmsRes;

/* compiled from: CellLocationUpdater */
public class a implements C0000c {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ Location f19a;
    public final /* synthetic */ OnPlengiListener b;
    public final /* synthetic */ c c;

    public a(c cVar, Location location, OnPlengiListener onPlengiListener) {
        this.c = cVar;
        this.f19a = location;
        this.b = onPlengiListener;
    }

    public void a(UplusLbmsRes uplusLbmsRes) {
        String lbs_lat = uplusLbmsRes.getLbs_lat();
        String lbs_lng = uplusLbmsRes.getLbs_lng();
        StringBuilder sb = new StringBuilder();
        sb.append("[UplusLbmsReq] lbs success ");
        sb.append(lbs_lat);
        sb.append(", ");
        sb.append(lbs_lng);
        sb.toString();
        if (lbs_lat != null && !lbs_lat.isEmpty() && lbs_lng != null && !lbs_lng.isEmpty()) {
            this.f19a.getCellInfo().setLbsMode(uplusLbmsRes.getPos_mode());
            this.f19a.getCellInfo().setLbsLat((double) Integer.parseInt(lbs_lat));
            this.f19a.getCellInfo().setLbsLng((double) Integer.parseInt(lbs_lng));
            this.f19a.setProvider("U+LBS");
            this.c.a(this.f19a, this.b);
        }
    }

    public void a(String str) {
        StringBuilder sb = new StringBuilder();
        sb.append("[UplusLbmsReq] ");
        sb.append(str);
        sb.append("! ");
        sb.toString();
        this.c.k;
        this.c.a(this.f19a, this.b);
    }
}