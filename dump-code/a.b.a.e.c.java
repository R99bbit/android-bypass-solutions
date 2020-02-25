package a.b.a.e;

import androidx.annotation.NonNull;
import com.google.android.gms.tasks.OnFailureListener;

/* compiled from: ActivityRecognitionMonitor */
class c implements OnFailureListener {
    public c(e eVar) {
    }

    public void onFailure(@NonNull Exception exc) {
        StringBuilder sb = new StringBuilder();
        sb.append("Transitions could not be unregistered: ");
        sb.append(exc);
        sb.toString();
    }
}