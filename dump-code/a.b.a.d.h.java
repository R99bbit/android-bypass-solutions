package a.b.a.d;

import a.b.a.f;
import android.content.Context;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import com.evernote.android.job.JobRequest;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.location.FusedLocationProviderClient;
import com.google.android.gms.location.LocationCallback;
import com.google.android.gms.location.LocationRequest;
import com.google.android.gms.location.LocationServices;
import com.loplat.placeengine.cloud.RequestMessage;

/* compiled from: GpsActiveUpdater */
public abstract class h {

    /* renamed from: a reason: collision with root package name */
    public Context f26a;
    public String b = RequestMessage.SEARCH_PLACE_INTERNAL;
    public boolean c;
    public boolean d;
    public LocationManager e;
    public a f;
    public LocationCallback g;
    public LocationRequest h;
    public FusedLocationProviderClient i;
    public Handler j;
    public Runnable k;
    public int l = 3000;

    /* compiled from: GpsActiveUpdater */
    private class a implements LocationListener {

        /* renamed from: a reason: collision with root package name */
        public boolean f27a = true;

        public a() {
        }

        public void onLocationChanged(Location location) {
            if (this.f27a) {
                this.f27a = false;
                h.a(h.this);
                if (h.this.a()) {
                    try {
                        ((LocationManager) h.this.f26a.getSystemService("location")).removeUpdates(this);
                    } catch (Exception unused) {
                    }
                }
                StringBuilder a2 = a.a.a.a.a.a("update location: ");
                a2.append(h.this.a(location));
                a2.toString();
                if (VERSION.SDK_INT < 18) {
                    h hVar = h.this;
                    hVar.a(hVar.f26a, hVar.b, location);
                } else if (location.isFromMockProvider()) {
                    h hVar2 = h.this;
                    hVar2.a(hVar2.f26a, hVar2.b);
                } else {
                    h hVar3 = h.this;
                    hVar3.a(hVar3.f26a, hVar3.b, location);
                }
            }
        }

        public void onProviderDisabled(String str) {
        }

        public void onProviderEnabled(String str) {
        }

        public void onStatusChanged(String str, int i, Bundle bundle) {
        }
    }

    public /* synthetic */ h(Context context, int i2, d dVar) {
        this.f26a = context;
        if (i2 == 0) {
            this.b = RequestMessage.SEARCH_PLACE_UNKNOWN;
        } else if (i2 == 1) {
            this.b = RequestMessage.SEARCH_PLACE;
        } else if (i2 == 2) {
            this.b = RequestMessage.SEARCH_PLACE_UNLOCK_SCREEN;
        } else if (i2 == 3) {
            this.b = RequestMessage.SEARCH_PLACE_INTERNAL;
        } else if (i2 == 4) {
            this.b = RequestMessage.SEARCH_PLACE_CHECK;
        } else if (i2 == 6) {
            this.b = RequestMessage.SEARCH_PLACE_CELL;
        } else if (i2 == 7) {
            this.b = RequestMessage.SEARCH_PLACE_GPS;
        }
    }

    public static /* synthetic */ void a(h hVar) {
        Runnable runnable = hVar.k;
        if (runnable != null) {
            Handler handler = hVar.j;
            if (handler != null) {
                handler.removeCallbacks(runnable);
            }
        }
    }

    public static /* synthetic */ void b(h hVar) {
        FusedLocationProviderClient fusedLocationProviderClient = hVar.i;
        if (fusedLocationProviderClient != null) {
            LocationCallback locationCallback = hVar.g;
            if (locationCallback != null) {
                fusedLocationProviderClient.removeLocationUpdates(locationCallback);
                hVar.g = null;
            }
        }
    }

    public abstract void a(Context context, String str);

    public abstract void a(Context context, String str, Location location);

    /* JADX WARNING: Failed to process nested try/catch */
    /* JADX WARNING: Missing exception handler attribute for start block: B:14:0x002f */
    /* JADX WARNING: Removed duplicated region for block: B:17:0x003b A[Catch:{ Exception -> 0x00e7, Error -> 0x00e3 }] */
    /* JADX WARNING: Removed duplicated region for block: B:30:0x0097 A[Catch:{ Exception -> 0x00e7, Error -> 0x00e3 }] */
    public void c() {
        if (a()) {
            if (this.e == null) {
                this.e = (LocationManager) this.f26a.getSystemService("location");
            }
            boolean z = false;
            this.c = false;
            this.d = false;
            this.d = this.e.isProviderEnabled("network");
            this.c = this.e.isProviderEnabled("gps");
            try {
                if (GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(this.f26a) != 0) {
                    if (this.i == null) {
                        this.i = LocationServices.getFusedLocationProviderClient(this.f26a);
                    }
                    if (a()) {
                        if (this.h == null) {
                            this.h = new LocationRequest();
                        }
                        this.h.setPriority(100).setInterval((long) (this.l * 2)).setFastestInterval((long) this.l);
                        if (this.g == null) {
                            this.g = new f(this);
                        }
                        this.i.requestLocationUpdates(this.h, this.g, Looper.myLooper());
                        a(0, this.l * 2);
                        return;
                    }
                    a(this.f26a, this.b);
                    return;
                }
                if (this.e != null && (this.d || this.c)) {
                    if (this.f == null) {
                        this.f = new a();
                    }
                    this.f.f27a = true;
                    if (this.d) {
                        this.e.requestLocationUpdates("network", 0, 0.0f, this.f);
                    }
                    if (this.c) {
                        this.e.requestLocationUpdates("gps", 0, 0.0f, this.f);
                    }
                    a(1, this.l);
                    z = true;
                }
                if (!z) {
                    a(this.f26a, this.b);
                }
            } catch (Exception unused) {
                b();
            } catch (Error unused2) {
                b();
            }
        }
    }

    public final void a(int i2, int i3) {
        this.j = new Handler();
        this.k = new g(this, i2);
        this.j.postDelayed(this.k, (long) i3);
    }

    public final void b() {
        Location d2 = f.d(this.f26a);
        if (d2 != null && !"dummy_provider".equals(d2.getProvider())) {
            StringBuilder a2 = a.a.a.a.a.a("check location: ");
            a2.append(a(d2));
            a2.toString();
            if (!(VERSION.SDK_INT < 17 ? System.currentTimeMillis() - d2.getTime() >= JobRequest.DEFAULT_BACKOFF_MS : (SystemClock.elapsedRealtimeNanos() - d2.getElapsedRealtimeNanos()) / 1000000 >= JobRequest.DEFAULT_BACKOFF_MS)) {
                StringBuilder a3 = a.a.a.a.a.a("latest location: ");
                a3.append(a(d2));
                a3.toString();
                a(this.f26a, this.b, d2);
                return;
            }
        }
        a(this.f26a, this.b);
    }

    public boolean a() {
        return f.a(this.f26a);
    }

    public String a(Location location) {
        long j2;
        if (location == null) {
            return "";
        }
        if (VERSION.SDK_INT >= 17) {
            j2 = (SystemClock.elapsedRealtimeNanos() - location.getElapsedRealtimeNanos()) / 1000000000;
        } else {
            j2 = (System.currentTimeMillis() - location.getTime()) / 1000;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(location.getTime());
        sb.append(", ");
        sb.append(j2);
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
        if (VERSION.SDK_INT < 26) {
            return valueOf;
        }
        StringBuilder sb2 = new StringBuilder();
        sb2.append(valueOf);
        sb2.append(", ");
        sb2.append(location.getVerticalAccuracyMeters());
        return sb2.toString();
    }
}