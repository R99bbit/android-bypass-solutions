package a.b.a;

import a.b.a.b.l;
import android.content.Context;
import com.loplat.placeengine.PlaceEngineBase;

/* compiled from: PlaceEngineBase */
class d implements a {
    public void a(Context context, String str) {
        boolean z = false;
        try {
            String userAdId = PlaceEngineBase.getUserAdId(context);
            if (userAdId == null || !userAdId.equals(str)) {
                z = true;
                PlaceEngineBase.setUserAdId(context, str);
                StringBuilder sb = new StringBuilder();
                sb.append("new advertisingId: ");
                sb.append(str);
                sb.toString();
            }
            if (!z) {
                return;
            }
        } catch (Exception unused) {
            if (!z) {
                return;
            }
        } catch (Throwable th) {
            if (z) {
                PlaceEngineBase.setANID(context, null);
                l.c(context);
            }
            throw th;
        }
        PlaceEngineBase.setANID(context, null);
        l.c(context);
    }

    public void a(Context context) {
        String userAdId = PlaceEngineBase.getUserAdId(context);
        String anid = PlaceEngineBase.getANID(context);
        if (userAdId != null && !userAdId.isEmpty()) {
            PlaceEngineBase.setANID(context, null);
            PlaceEngineBase.setUserAdId(context, null);
            anid = null;
        }
        if (anid == null) {
            l.c(context);
        }
    }
}