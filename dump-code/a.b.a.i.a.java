package a.b.a.i;

import com.loplat.placeengine.wifi.WifiType;
import java.util.Iterator;
import java.util.List;

/* compiled from: WifiScanAnalysis */
public class a {

    /* renamed from: a reason: collision with root package name */
    public static float f48a = 0.3f;
    public static float b = 0.3f;

    /* renamed from: a.b.a.i.a$a reason: collision with other inner class name */
    /* compiled from: WifiScanAnalysis */
    private static class C0001a {

        /* renamed from: a reason: collision with root package name */
        public int f49a;
        public int b;
        public int c;

        public C0001a(int i, int i2, int i3, String str) {
            this.f49a = i;
            this.b = i2;
            this.c = i3;
        }
    }

    public static float a(List<WifiType> list, List<WifiType> list2) {
        float f = 0.0f;
        if (list == null || list.isEmpty() || list2 == null || list2.isEmpty()) {
            return 0.0f;
        }
        float f2 = 0.0f;
        float f3 = 0.0f;
        float f4 = 0.0f;
        float f5 = 0.0f;
        for (WifiType next : list) {
            int i = next.level;
            if (i > -91) {
                float f6 = (float) (i + 91);
                float f7 = f6 * f6;
                f2 += f7;
                Iterator<WifiType> it = list2.iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    WifiType next2 = it.next();
                    if (next.BSSID == null) {
                        StringBuilder a2 = a.a.a.a.a.a("~~~~~~~~~~~~~~~~ DEAD1 ~~~~~~~~~: ");
                        a2.append(next.BSSID);
                        a2.append(", ");
                        a2.append(next.level);
                        a2.append(", ");
                        a2.append(next.BSSID);
                        a2.toString();
                        break;
                    } else if (next2 == null || next2.BSSID == null) {
                        StringBuilder a3 = a.a.a.a.a.a("~~~~~~~~~~~~~~~~ DEAD2 ~~~~~~~~~: ");
                        a3.append(next2.BSSID);
                        a3.append(", ");
                        a3.append(next2.level);
                        a3.append(", ");
                        a3.append(next2.BSSID);
                        a3.toString();
                    } else if (next.equals(next2)) {
                        int i2 = next2.level;
                        if (i2 > -91) {
                            float f8 = (float) (i2 + 91);
                            f5 += f6 * f8;
                            f3 += f7;
                            f4 += f8 * f8;
                        }
                    }
                }
            }
        }
        float f9 = 0.0f;
        for (WifiType wifiType : list2) {
            int i3 = wifiType.level;
            if (i3 > -91) {
                float f10 = (float) (i3 + 91);
                f9 += f10 * f10;
            }
        }
        float f11 = (f2 + f9) - f5;
        int i4 = (f11 > 0.0f ? 1 : (f11 == 0.0f ? 0 : -1));
        float f12 = i4 > 0 ? f5 / f11 : 0.0f;
        float f13 = (f3 + f4) - f5;
        int i5 = (f13 > 0.0f ? 1 : (f13 == 0.0f ? 0 : -1));
        float f14 = i5 > 0 ? f5 / f13 : 0.0f;
        if (i4 > 0 && i5 > 0) {
            float f15 = (float) (((double) f13) * 1.3d);
            float f16 = f11 + f15;
            f12 = ((f14 * f15) / f16) + ((f11 / f16) * f12);
        }
        float sqrt = (float) (Math.sqrt((double) f9) * Math.sqrt((double) f2));
        if (sqrt != 0.0f) {
            f = f5 / sqrt;
        }
        float f17 = (f * 0.4f) + (f12 * 0.6f);
        StringBuilder sb = new StringBuilder();
        sb.append("similarity: ");
        sb.append(f17);
        sb.toString();
        return f17;
    }
}