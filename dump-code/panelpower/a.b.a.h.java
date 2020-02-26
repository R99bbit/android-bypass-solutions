package a.b.a;

import a.b.a.g.a;
import com.loplat.placeengine.wifi.WifiType;
import java.util.List;

/* compiled from: ProcessedWifiScanResult */
public class h {

    /* renamed from: a reason: collision with root package name */
    public int f42a = -1;
    public int b;
    public List<WifiType> c;
    public float d;

    public h(int i) {
        this.b = i;
    }

    public void a(List<WifiType> list) {
        this.c = list;
        this.d = a.a(this.c);
    }

    public boolean a() {
        List<WifiType> list = this.c;
        return list != null && !list.isEmpty() && ((double) this.d) > 0.0d;
    }
}