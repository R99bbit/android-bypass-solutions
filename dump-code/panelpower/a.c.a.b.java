package a.c.a;

import android.app.AlertDialog;
import android.view.View;
import android.view.View.OnClickListener;
import com.plengi.app.GuideDialogActivity;

/* compiled from: GuideDialogActivity */
class b implements OnClickListener {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ AlertDialog f51a;

    public b(GuideDialogActivity guideDialogActivity, AlertDialog alertDialog) {
        this.f51a = alertDialog;
    }

    public void onClick(View view) {
        this.f51a.dismiss();
    }
}