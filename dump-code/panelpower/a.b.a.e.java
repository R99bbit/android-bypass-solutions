package a.b.a;

import a.b.a.d.j;
import a.b.a.g.a;
import android.content.Context;
import android.location.Location;
import android.os.Build.VERSION;
import com.loplat.placeengine.PlengiResponse.Place;

/* compiled from: PlaceMonitorMode */
class e implements j {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ Place f29a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Context c;

    public e(Place place, int i, Context context) {
        this.f29a = place;
        this.b = i;
        this.c = context;
    }

    /* JADX WARNING: Removed duplicated region for block: B:20:0x0058  */
    public void a(Location location) {
        boolean z;
        if (location != null) {
            Place place = this.f29a;
            boolean z2 = false;
            if (!"dummy_provider".equals(location.getProvider()) && place.lat != 0.0d && place.lng != 0.0d && location.hasAccuracy() && location.getAccuracy() < 400.0f) {
                if (VERSION.SDK_INT >= 17) {
                    z = false;
                    if (!z) {
                        Location location2 = new Location("dummy_provider");
                        location2.setLatitude(place.lat);
                        location2.setLongitude(place.lng);
                        float distanceTo = location2.distanceTo(location);
                        StringBuilder sb = new StringBuilder();
                        sb.append("distance difference: ");
                        sb.append(distanceTo);
                        sb.toString();
                        if (distanceTo > 400.0f) {
                            z2 = true;
                        }
                    }
                } else {
                    z = false;
                    if (!z) {
                    }
                }
                z = true;
                if (!z) {
                }
            }
            if (z2) {
                int i = this.b;
                if (i == 0) {
                    f.a(this.c, this.f29a);
                    f.b(this.c);
                    a.a(this.c, (String) null);
                } else if (i == 1) {
                    g.c(this.c, this.f29a);
                }
            }
        }
    }
}