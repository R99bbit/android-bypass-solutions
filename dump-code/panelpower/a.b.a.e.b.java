package a.b.a.e;

import com.google.android.gms.tasks.OnFailureListener;

/* compiled from: ActivityRecognitionMonitor */
class b implements OnFailureListener {
    public b(e eVar) {
    }

    public void onFailure(Exception exc) {
        StringBuilder sb = new StringBuilder();
        sb.append("Transitions Api could not be registered: ");
        sb.append(exc);
        sb.toString();
    }
}