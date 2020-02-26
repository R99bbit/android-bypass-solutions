package a.b.a.i;

import java.util.Comparator;

/* compiled from: WifiScanManager */
class b implements Comparator<a> {
    public int compare(Object obj, Object obj2) {
        int i = ((a) obj).c;
        int i2 = ((a) obj2).c;
        int i3 = i > i2 ? 1 : i < i2 ? -1 : 0;
        return i3 * -1;
    }
}