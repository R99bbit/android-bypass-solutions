package a.b.a.d;

import a.b.a.b.l;
import a.b.a.e.e;
import android.content.Context;
import android.location.Location;
import com.loplat.placeengine.cloud.RequestMessage;
import java.util.List;

/* compiled from: GpsActiveUpdater */
public final class d extends h {
    public final /* synthetic */ String m;
    public final /* synthetic */ List n;

    /* JADX WARN: Illegal instructions before constructor call commented (this can break semantics) */
    public d(Context context, int i, String str, List list) {
        // this.m = str;
        // this.n = list;
        super(context, i, null);
    }

    public void a(Context context, String str, Location location) {
        if (str.equals(RequestMessage.SEARCH_PLACE_GPS)) {
            e.a(context).a(location, this.m);
        } else {
            l.a(context, str, this.n, location, this.m);
        }
    }

    public void a(Context context, String str) {
        if (str.equals(RequestMessage.SEARCH_PLACE_GPS)) {
            e.a(context).a(null, this.m);
        } else {
            l.a(context, str, this.n, null, this.m);
        }
    }
}