package a.b.a.d;

import android.location.Location;
import android.os.Build.VERSION;
import android.os.SystemClock;
import com.google.android.gms.tasks.OnSuccessListener;

/* compiled from: LocationUtility */
public final class i implements OnSuccessListener<Location> {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ j f28a;

    public i(j jVar) {
        this.f28a = jVar;
    }

    public void onSuccess(Object obj) {
        long j;
        Location location = (Location) obj;
        if (location != null) {
            if (VERSION.SDK_INT >= 17) {
                j = (SystemClock.elapsedRealtimeNanos() - location.getElapsedRealtimeNanos()) / 1000000000;
            } else {
                j = (System.currentTimeMillis() - location.getTime()) / 1000;
            }
            StringBuilder sb = new StringBuilder();
            sb.append(location.getTime());
            sb.append(", ");
            sb.append(j);
            sb.append("\ucd08, ");
            sb.append(location.getProvider());
            sb.append(", ");
            sb.append(location.getLatitude());
            sb.append(", ");
            sb.append(location.getLongitude());
            sb.append(", ");
            sb.append(location.getAccuracy());
            sb.append(", ");
            sb.append(location.getAltitude());
            String valueOf = String.valueOf(sb.toString());
            if (VERSION.SDK_INT >= 26) {
                StringBuilder sb2 = new StringBuilder();
                sb2.append(valueOf);
                sb2.append(", ");
                sb2.append(location.getVerticalAccuracyMeters());
                sb2.toString();
            }
        }
        ((e) this.f28a).a(location);
    }
}