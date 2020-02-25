package a.b.a.d;

import a.b.a.b.l;
import android.content.Context;
import android.location.Location;
import com.loplat.placeengine.OnPlengiListener;
import java.util.List;

/* compiled from: GpsActiveUpdater */
public final class e extends h {
    public final /* synthetic */ String m;
    public final /* synthetic */ String n;
    public final /* synthetic */ List o;
    public final /* synthetic */ OnPlengiListener p;

    /* JADX WARN: Illegal instructions before constructor call commented (this can break semantics) */
    public e(Context context, int i, String str, String str2, List list, OnPlengiListener onPlengiListener) {
        // this.m = str;
        // this.n = str2;
        // this.o = list;
        // this.p = onPlengiListener;
        super(context, i, null);
    }

    public void a(Context context, String str, Location location) {
        String str2 = this.m;
        String str3 = this.n;
        l.a(context, this.o, location, this.p);
    }

    public void a(Context context, String str) {
        String str2 = this.m;
        String str3 = this.n;
        l.a(context, this.o, (Location) null, this.p);
    }
}