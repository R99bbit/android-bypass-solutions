package a.b.a.f;

import android.content.Intent;
import android.os.Build.VERSION;
import android.os.Handler;
import com.loplat.placeengine.service.ForegroundService;
import java.util.List;

/* compiled from: ForegroundService */
class c implements Runnable {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ Intent f34a;
    public final /* synthetic */ ForegroundService b;

    public c(ForegroundService foregroundService, Intent intent) {
        this.b = foregroundService;
        this.f34a = intent;
    }

    public void run() {
        boolean hasExtra = this.f34a.hasExtra("engine_progress");
        boolean hasExtra2 = this.f34a.hasExtra("update_gps_progress");
        if (hasExtra || hasExtra2) {
            this.b.b();
            if (hasExtra) {
                try {
                    ForegroundService.a(this.b, this.f34a.getIntExtra("engine_progress", 0));
                } catch (Error unused) {
                    this.b.c();
                    if (VERSION.SDK_INT >= 28 && this.b.i) {
                        new Handler().postDelayed(new b(this), 1000);
                        return;
                    }
                    return;
                } catch (Exception unused2) {
                    this.b.c();
                    if (VERSION.SDK_INT >= 28 && this.b.i) {
                        new Handler().postDelayed(new b(this), 1000);
                        return;
                    }
                    return;
                } catch (Throwable th) {
                    this.b.c();
                    if (VERSION.SDK_INT >= 28 && this.b.i) {
                        new Handler().postDelayed(new b(this), 1000);
                    }
                    throw th;
                }
            } else if (hasExtra2) {
                List list = (List) this.f34a.getSerializableExtra("update_gps_progress");
                int intExtra = this.f34a.getIntExtra("engine_progress_type", 0);
                String str = null;
                if (this.f34a.hasExtra("activity_recognition_log")) {
                    str = this.f34a.getStringExtra("activity_recognition_log");
                }
                this.b.a(list, intExtra, str);
            }
            this.b.c();
            if (VERSION.SDK_INT >= 28 && this.b.i) {
                new Handler().postDelayed(new b(this), 1000);
            }
        }
    }
}