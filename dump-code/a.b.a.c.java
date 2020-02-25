package a.b.a;

import a.b.a.g.a;
import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.res.Configuration;
import android.os.Build.VERSION;
import com.loplat.placeengine.PlaceEngineBase;
import com.loplat.placeengine.service.PeriodicJobService;

/* compiled from: PlaceEngineBase */
class c implements ComponentCallbacks2 {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ Context f17a;

    public c(Context context) {
        this.f17a = context;
    }

    public void onConfigurationChanged(Configuration configuration) {
    }

    public void onLowMemory() {
    }

    public void onTrimMemory(int i) {
        StringBuilder sb = new StringBuilder();
        sb.append("PlaceEngineBase onTrimMemory: ");
        sb.append(i);
        sb.toString();
        int engineStatus = PlaceEngineBase.getEngineStatus(this.f17a);
        if ((engineStatus == 1 || engineStatus == 2) && VERSION.SDK_INT >= 26 && a.m(this.f17a) >= 26) {
            PeriodicJobService.b(this.f17a);
        }
    }
}