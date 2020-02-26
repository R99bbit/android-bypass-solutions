package com.plengi.app;

import a.b.a.f.a;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import com.loplat.placeengine.R;

@RequiresApi(api = 26)
public class GuideDialogActivity extends Activity {
    public void finish() {
        super.finish();
        overridePendingTransition(0, 0);
    }

    public void onCreate(@Nullable Bundle bundle) {
        Drawable drawable;
        super.onCreate(bundle);
        overridePendingTransition(0, 0);
        AlertDialog show = new Builder(this).setView(R.layout.dialog_guide).setOnDismissListener(new a(this)).show();
        try {
            drawable = getPackageManager().getApplicationIcon(getPackageName());
        } catch (NameNotFoundException e) {
            e.printStackTrace();
            drawable = null;
        }
        ApplicationInfo applicationInfo = getApplicationInfo();
        int i = applicationInfo.labelRes;
        String charSequence = i == 0 ? applicationInfo.nonLocalizedLabel.toString() : getString(i);
        int i2 = a.c;
        if (i2 == 0) {
            i2 = R.string.channel_name_default;
        }
        String string = getString(i2);
        int i3 = a.e;
        if (i3 == 0) {
            i3 = R.string.channel_guide;
        }
        String string2 = getString(i3);
        if (drawable != null) {
            ((ImageView) show.findViewById(R.id.img_app_icon)).setImageDrawable(drawable);
        }
        ((TextView) show.findViewById(R.id.text_guide_description)).setText(string2);
        ((TextView) show.findViewById(R.id.text_channel_name_1)).setText(string);
        ((TextView) show.findViewById(R.id.text_channel_name_2)).setText(string);
        ((TextView) show.findViewById(R.id.text_app_name)).setText(charSequence);
        show.findViewById(R.id.btn_close_dialog).setOnClickListener(new b(this, show));
    }
}