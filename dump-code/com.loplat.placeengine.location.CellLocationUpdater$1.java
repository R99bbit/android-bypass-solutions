package com.loplat.placeengine.location;

import a.b.a.d.c;
import java.util.LinkedHashMap;
import java.util.Map.Entry;

class CellLocationUpdater$1 extends LinkedHashMap {
    public final /* synthetic */ c this$0;

    /* JADX WARN: Illegal instructions before constructor call commented (this can break semantics) */
    public CellLocationUpdater$1(c cVar, int i, float f, boolean z) {
        // this.this$0 = cVar;
        super(i, f, z);
    }

    public boolean removeEldestEntry(Entry entry) {
        boolean z = size() > 10;
        if (z) {
            this.this$0.g;
            new Object[1][0] = entry.getKey();
            remove(entry.getKey());
        }
        return z;
    }
}