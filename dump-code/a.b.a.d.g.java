package a.b.a.d;

import android.location.LocationManager;

/* compiled from: GpsActiveUpdater */
class g implements Runnable {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ int f25a;
    public final /* synthetic */ h b;

    public g(h hVar, int i) {
        this.b = hVar;
        this.f25a = i;
    }

    public void run() {
        if (this.f25a == 0) {
            h.b(this.b);
        } else {
            h hVar = this.b;
            a aVar = hVar.f;
            if (aVar != null && aVar.f27a) {
                aVar.f27a = false;
                if (hVar.a()) {
                    try {
                        ((LocationManager) this.b.f26a.getSystemService("location")).removeUpdates(this.b.f);
                    } catch (Exception unused) {
                    }
                }
            }
        }
        this.b.b();
    }
}