package a.b.a.f;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.IBinder;
import com.loplat.placeengine.service.ForegroundService;

/* compiled from: ForegroundService */
class g implements ServiceConnection {
    public void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        ForegroundService.d = ForegroundService.this;
        ForegroundService.e = true;
    }

    public void onServiceDisconnected(ComponentName componentName) {
        ForegroundService.e = false;
        String str = ForegroundService.f56a;
        new Object[1][0] = "FG service disconnected";
    }
}