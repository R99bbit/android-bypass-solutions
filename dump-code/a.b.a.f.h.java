package a.b.a.f;

import android.content.Context;
import androidx.core.app.NotificationManagerCompat;

/* compiled from: SearchPlaceNotification */
public final class h implements Runnable {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ Context f38a;

    public h(Context context) {
        this.f38a = context;
    }

    public void run() {
        NotificationManagerCompat.from(this.f38a).cancel(190828);
    }
}