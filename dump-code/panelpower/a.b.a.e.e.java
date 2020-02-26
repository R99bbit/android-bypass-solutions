package a.b.a.e;

import a.b.a.b.l;
import a.b.a.c.a;
import a.b.a.f;
import android.annotation.SuppressLint;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.location.Location;
import android.os.Build.VERSION;
import android.os.SystemClock;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.google.android.gms.location.ActivityRecognition;
import com.google.android.gms.location.ActivityTransition.Builder;
import com.google.android.gms.location.ActivityTransitionEvent;
import com.google.android.gms.location.ActivityTransitionRequest;
import com.google.android.gms.tasks.Task;
import com.loplat.placeengine.EventReceiver;
import com.loplat.placeengine.cloud.RequestMessage;
import java.util.ArrayList;
import java.util.List;

/* compiled from: ActivityRecognitionMonitor */
public class e {

    /* renamed from: a reason: collision with root package name */
    public static e f30a;
    public static ActivityTransitionEvent b;
    @Nullable
    public static String c;
    public Context d;
    public int e = 300;
    public int f = 240;

    public e(Context context) {
        this.d = context;
    }

    public static int a(int i) {
        switch (i) {
            case 0:
                return 4;
            case 1:
                return 3;
            case 2:
                return 1;
            case 3:
                return 0;
            case 4:
                return -1;
            case 5:
                return 0;
            case 7:
                return 1;
            case 8:
                return 2;
            default:
                return -1;
        }
    }

    public static synchronized e a(Context context) {
        e eVar;
        synchronized (e.class) {
            try {
                if (f30a == null) {
                    f30a = new e(context);
                }
                eVar = f30a;
            }
        }
        return eVar;
    }

    @SuppressLint({"MissingPermission"})
    public void b() {
        try {
            if (b(this.d)) {
                Intent intent = new Intent(this.d, EventReceiver.class);
                intent.setAction("com.loplat.placeengine.event.activity_recognition");
                ActivityRecognition.getClient(this.d).removeActivityTransitionUpdates(PendingIntent.getBroadcast(this.d, 0, intent, 0)).addOnSuccessListener(new d(this)).addOnFailureListener(new c(this));
            }
        } catch (Error | Exception unused) {
        }
    }

    @SuppressLint({"MissingPermission"})
    public void a() {
        this.e = a.b(this.d).h();
        this.f = a.b(this.d).i();
        try {
            if (b(this.d)) {
                ArrayList arrayList = new ArrayList();
                arrayList.add(new Builder().setActivityType(7).setActivityTransition(0).build());
                arrayList.add(new Builder().setActivityType(7).setActivityTransition(1).build());
                arrayList.add(new Builder().setActivityType(3).setActivityTransition(0).build());
                arrayList.add(new Builder().setActivityType(3).setActivityTransition(1).build());
                arrayList.add(new Builder().setActivityType(0).setActivityTransition(0).build());
                arrayList.add(new Builder().setActivityType(0).setActivityTransition(1).build());
                Intent intent = new Intent(this.d, EventReceiver.class);
                intent.setAction("com.loplat.placeengine.event.activity_recognition");
                Task<Void> requestActivityTransitionUpdates = ActivityRecognition.getClient(this.d).requestActivityTransitionUpdates(new ActivityTransitionRequest(arrayList), PendingIntent.getBroadcast(this.d, 0, intent, 0));
                requestActivityTransitionUpdates.addOnSuccessListener(new a(this));
                requestActivityTransitionUpdates.addOnFailureListener(new b(this));
            }
        } catch (Error | Exception unused) {
        }
    }

    public static boolean b(Context context) {
        try {
            if (VERSION.SDK_INT >= 23) {
                if (context.checkSelfPermission("com.google.android.gms.permission.ACTIVITY_RECOGNITION") == 0) {
                    return true;
                }
            }
        } catch (Error | Exception unused) {
        }
        return false;
    }

    public void a(List<ActivityTransitionEvent> list) {
        if (list != null) {
            StringBuilder sb = new StringBuilder();
            if (b == null) {
                sb.append("[latest=null]");
                b = list.get(0);
            } else {
                sb.append("[latest=");
                sb.append(a(b));
                sb.append("]");
            }
            String str = null;
            for (ActivityTransitionEvent next : list) {
                sb.append(", ");
                sb.append(a(next));
                if (next.getTransitionType() == 0 && a(b.getActivityType()) > a(next.getActivityType())) {
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append(b.getActivityType());
                    sb2.append(",");
                    sb2.append(next.getActivityType());
                    str = sb2.toString();
                }
                b = next;
            }
            if (str == null) {
                return;
            }
            if (a.b(this.d).q() > 0) {
                a(str);
            } else {
                c = str;
            }
        }
    }

    public void a(@NonNull String str) {
        Location l = a.b(this.d).l();
        if ((SystemClock.elapsedRealtime() - a.b(this.d).k()) / 1000 > ((long) this.f) && l != null) {
            Context context = this.d;
            l.j = context;
            f.a(context, null, 7, str);
        }
    }

    public void a(@Nullable Location location, @Nullable String str) {
        if (str == null) {
            str = "4,4";
        }
        Location l = a.b(this.d).l();
        if (l == null) {
            return;
        }
        if (location == null || location.distanceTo(l) > ((float) this.e)) {
            c = null;
            l.a(this.d, RequestMessage.SEARCH_PLACE_GPS, null, location, str);
        }
    }

    public static String a(ActivityTransitionEvent activityTransitionEvent) {
        String str;
        StringBuilder sb = new StringBuilder();
        int activityType = activityTransitionEvent.getActivityType();
        switch (activityType) {
            case 0:
                str = "IN_VEHICLE";
                break;
            case 1:
                str = "ON_BICYCLE";
                break;
            case 2:
                str = "ON_FOOT";
                break;
            case 3:
                str = "STILL";
                break;
            case 4:
                str = "UNKNOWN";
                break;
            case 5:
                str = "TILTING";
                break;
            case 7:
                str = "WALKING";
                break;
            case 8:
                str = "RUNNING";
                break;
            default:
                str = String.valueOf(activityType);
                break;
        }
        sb.append(str);
        sb.append("(");
        int transitionType = activityTransitionEvent.getTransitionType();
        String str2 = transitionType != 0 ? transitionType != 1 ? String.valueOf(transitionType) : "EXIT" : "ENTER";
        sb.append(str2);
        sb.append(")");
        return sb.toString();
    }
}