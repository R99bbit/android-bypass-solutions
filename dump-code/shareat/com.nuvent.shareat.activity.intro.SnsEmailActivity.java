package com.nuvent.shareat.activity.intro;

import android.graphics.Color;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewTreeObserver.OnGlobalLayoutListener;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.model.SnsModel;
import net.xenix.util.ValidUtil;

public class SnsEmailActivity extends BaseActivity {
    boolean isOpened = false;

    public void onBackPressed() {
        finish(R.anim.fade_in_activity, R.anim.fade_out_activity);
    }

    public void onClickConfirm(View view) {
        checkValue();
    }

    public void setListenerToRootView() {
        final View activityRootView = getWindow().getDecorView().findViewById(16908290);
        activityRootView.getViewTreeObserver().addOnGlobalLayoutListener(new OnGlobalLayoutListener() {
            public void onGlobalLayout() {
                if (activityRootView.getRootView().getHeight() - activityRootView.getHeight() > 300) {
                    SnsEmailActivity.this.isOpened = true;
                } else if (SnsEmailActivity.this.isOpened) {
                    SnsEmailActivity.this.isOpened = false;
                    if (TextUtils.isEmpty(((EditText) SnsEmailActivity.this.findViewById(R.id.emailField)).getText())) {
                        SnsEmailActivity.this.findViewById(R.id.emailField).setSelected(false);
                        ((TextView) SnsEmailActivity.this.findViewById(R.id.emailLabel)).setTextColor(Color.parseColor("#7cffffff"));
                    }
                }
            }
        });
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_email);
        findViewById(R.id.confirmButton).setEnabled(false);
        findViewById(R.id.emailField).setOnClickListener(new OnClickListener() {
            public void onClick(View view) {
                view.setSelected(true);
                ((TextView) SnsEmailActivity.this.findViewById(R.id.emailLabel)).setTextColor(-1);
            }
        });
        ((EditText) findViewById(R.id.emailField)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                SnsEmailActivity.this.findViewById(R.id.confirmButton).setEnabled(ValidUtil.isValidEmail(s.toString()));
            }
        });
        setListenerToRootView();
    }

    private void checkValue() {
        String email = ((EditText) findViewById(R.id.emailField)).getText().toString().trim();
        if (email.isEmpty()) {
            Toast.makeText(this, "\uc774\uba54\uc77c\uc744 \uc785\ub825\ud574\uc8fc\uc138\uc694.", 0).show();
            return;
        }
        if (!ValidUtil.isValidEmail(email)) {
            Toast.makeText(this, "\uc62c\ubc14\ub978 \uc774\uba54\uc77c\uc744 \uc785\ub825\ud574\uc8fc\uc138\uc694.", 0).show();
        }
        SnsModel model = (SnsModel) getIntent().getSerializableExtra("model");
        model.setUserEmail(email);
        getIntent().putExtra("model", model);
        setResult(-1, getIntent());
        onBackPressed();
    }
}