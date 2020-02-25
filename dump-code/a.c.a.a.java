package a.c.a;

import android.content.DialogInterface;
import android.content.DialogInterface.OnDismissListener;
import com.plengi.app.GuideDialogActivity;

/* compiled from: GuideDialogActivity */
class a implements OnDismissListener {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ GuideDialogActivity f50a;

    public a(GuideDialogActivity guideDialogActivity) {
        this.f50a = guideDialogActivity;
    }

    public void onDismiss(DialogInterface dialogInterface) {
        this.f50a.finish();
    }
}