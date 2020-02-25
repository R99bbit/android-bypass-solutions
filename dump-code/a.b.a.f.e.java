package a.b.a.f;

import androidx.core.app.NotificationManagerCompat;
import com.loplat.placeengine.service.ForegroundService;

/* compiled from: ForegroundService */
class e implements Runnable {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ ForegroundService f36a;

    public e(ForegroundService foregroundService) {
        this.f36a = foregroundService;
    }

    public void run() {
        NotificationManagerCompat.from(this.f36a.h).cancel(141224);
    }
}