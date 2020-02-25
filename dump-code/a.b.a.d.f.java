package a.b.a.d;

import a.a.a.a.a;
import android.annotation.SuppressLint;
import android.location.Location;
import android.os.Build.VERSION;
import com.google.android.gms.location.LocationAvailability;
import com.google.android.gms.location.LocationCallback;
import com.google.android.gms.location.LocationResult;

/* compiled from: GpsActiveUpdater */
class f extends LocationCallback {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ h f24a;

    public f(h hVar) {
        this.f24a = hVar;
    }

    @SuppressLint({"MissingPermission"})
    public void onLocationAvailability(LocationAvailability locationAvailability) {
        if (!locationAvailability.isLocationAvailable()) {
            h.a(this.f24a);
            h.b(this.f24a);
            h hVar = this.f24a;
            hVar.a(hVar.f26a, hVar.b);
        }
    }

    public void onLocationResult(LocationResult locationResult) {
        super.onLocationResult(locationResult);
        h.a(this.f24a);
        h.b(this.f24a);
        if (locationResult != null) {
            Location lastLocation = locationResult.getLastLocation();
            StringBuilder a2 = a.a("location result: ");
            a2.append(this.f24a.a(lastLocation));
            a2.toString();
            if (VERSION.SDK_INT < 18) {
                h hVar = this.f24a;
                hVar.a(hVar.f26a, hVar.b, lastLocation);
            } else if (lastLocation.isFromMockProvider()) {
                h hVar2 = this.f24a;
                hVar2.a(hVar2.f26a, hVar2.b);
            } else {
                h hVar3 = this.f24a;
                hVar3.a(hVar3.f26a, hVar3.b, lastLocation);
            }
        } else {
            this.f24a.b();
        }
    }
}