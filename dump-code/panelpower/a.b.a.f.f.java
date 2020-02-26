package a.b.a.f;

import androidx.core.app.NotificationManagerCompat;
import com.loplat.placeengine.service.ForegroundService;

/* compiled from: ForegroundService */
class f implements Runnable {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ ForegroundService f37a;

    public f(ForegroundService foregroundService) {
        this.f37a = foregroundService;
    }

    public void run() {
        NotificationManagerCompat.from(this.f37a.h).cancel(141224);
    }
}