package a.b.a;

import android.content.Context;
import android.content.Intent;
import com.loplat.placeengine.EventReceiver;

/* compiled from: EventReceiver */
class b implements Runnable {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ Context f4a;
    public final /* synthetic */ Intent b;
    public final /* synthetic */ EventReceiver c;

    public b(EventReceiver eventReceiver, Context context, Intent intent) {
        this.c = eventReceiver;
        this.f4a = context;
        this.b = intent;
    }

    public void run() {
        this.c.a(this.f4a, this.b.getAction(), this.b);
    }
}