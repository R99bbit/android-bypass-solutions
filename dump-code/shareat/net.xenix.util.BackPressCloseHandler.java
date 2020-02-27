package net.xenix.util;

import android.app.Activity;
import android.widget.Toast;
import com.nuvent.shareat.activity.BaseActivity;

public class BackPressCloseHandler {
    private Activity activity;
    private long backKeyPressedTime = 0;
    private Toast toast;

    public BackPressCloseHandler(Activity context) {
        this.activity = context;
    }

    public void onBackPressed() {
        if (System.currentTimeMillis() > this.backKeyPressedTime + 2000) {
            this.backKeyPressedTime = System.currentTimeMillis();
            showGuide();
        } else if (System.currentTimeMillis() <= this.backKeyPressedTime + 2000) {
            ((BaseActivity) this.activity).finish(false);
            this.toast.cancel();
        }
    }

    public void showGuide() {
        this.toast = Toast.makeText(this.activity, "'\ub4a4\ub85c'\ubc84\ud2bc\uc744 \ud55c\ubc88 \ub354 \ub204\ub974\uc2dc\uba74 \uc885\ub8cc\ub429\ub2c8\ub2e4.", 0);
        this.toast.show();
    }
}