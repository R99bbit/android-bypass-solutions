package org.acra;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.app.NotificationManager;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.DialogInterface.OnDismissListener;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup.LayoutParams;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.IOException;
import org.acra.collector.CrashReportData;
import org.acra.util.ToastSender;

public class CrashReportDialog extends Activity implements OnClickListener, OnDismissListener {
    private static final String STATE_COMMENT = "comment";
    private static final String STATE_EMAIL = "email";
    AlertDialog mDialog;
    String mReportFileName;
    private SharedPreferences prefs;
    private EditText userComment;
    private EditText userEmail;

    /* access modifiers changed from: protected */
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (getIntent().getBooleanExtra("FORCE_CANCEL", false)) {
            ACRA.log.d(ACRA.LOG_TAG, "Forced reports deletion.");
            cancelReports();
            finish();
            return;
        }
        this.mReportFileName = getIntent().getStringExtra("REPORT_FILE_NAME");
        String str = ACRA.LOG_TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("Opening CrashReportDialog for ");
        sb.append(this.mReportFileName);
        Log.d(str, sb.toString());
        if (this.mReportFileName == null) {
            finish();
        }
        Builder builder = new Builder(this);
        int resDialogTitle = ACRA.getConfig().resDialogTitle();
        if (resDialogTitle != 0) {
            builder.setTitle(resDialogTitle);
        }
        int resDialogIcon = ACRA.getConfig().resDialogIcon();
        if (resDialogIcon != 0) {
            builder.setIcon(resDialogIcon);
        }
        builder.setView(buildCustomView(bundle));
        builder.setPositiveButton(17039370, this);
        builder.setNegativeButton(17039360, this);
        cancelNotification();
        this.mDialog = builder.create();
        this.mDialog.setCanceledOnTouchOutside(false);
        this.mDialog.setOnDismissListener(this);
        this.mDialog.show();
    }

    private View buildCustomView(Bundle bundle) {
        LinearLayout linearLayout = new LinearLayout(this);
        linearLayout.setOrientation(1);
        linearLayout.setPadding(10, 10, 10, 10);
        linearLayout.setLayoutParams(new LayoutParams(-1, -2));
        linearLayout.setFocusable(true);
        linearLayout.setFocusableInTouchMode(true);
        ScrollView scrollView = new ScrollView(this);
        linearLayout.addView(scrollView, new LinearLayout.LayoutParams(-1, -1, 1.0f));
        LinearLayout linearLayout2 = new LinearLayout(this);
        linearLayout2.setOrientation(1);
        scrollView.addView(linearLayout2);
        TextView textView = new TextView(this);
        int resDialogText = ACRA.getConfig().resDialogText();
        if (resDialogText != 0) {
            textView.setText(getText(resDialogText));
        }
        linearLayout2.addView(textView);
        int resDialogCommentPrompt = ACRA.getConfig().resDialogCommentPrompt();
        if (resDialogCommentPrompt != 0) {
            TextView textView2 = new TextView(this);
            textView2.setText(getText(resDialogCommentPrompt));
            textView2.setPadding(textView2.getPaddingLeft(), 10, textView2.getPaddingRight(), textView2.getPaddingBottom());
            linearLayout2.addView(textView2, new LinearLayout.LayoutParams(-1, -2));
            this.userComment = new EditText(this);
            this.userComment.setLines(2);
            if (bundle != null) {
                String string = bundle.getString(STATE_COMMENT);
                if (string != null) {
                    this.userComment.setText(string);
                }
            }
            linearLayout2.addView(this.userComment);
        }
        int resDialogEmailPrompt = ACRA.getConfig().resDialogEmailPrompt();
        if (resDialogEmailPrompt != 0) {
            TextView textView3 = new TextView(this);
            textView3.setText(getText(resDialogEmailPrompt));
            textView3.setPadding(textView3.getPaddingLeft(), 10, textView3.getPaddingRight(), textView3.getPaddingBottom());
            linearLayout2.addView(textView3);
            this.userEmail = new EditText(this);
            this.userEmail.setSingleLine();
            this.userEmail.setInputType(33);
            this.prefs = getSharedPreferences(ACRA.getConfig().sharedPreferencesName(), ACRA.getConfig().sharedPreferencesMode());
            String str = null;
            if (bundle != null) {
                str = bundle.getString("email");
            }
            if (str != null) {
                this.userEmail.setText(str);
            } else {
                this.userEmail.setText(this.prefs.getString(ACRA.PREF_USER_EMAIL_ADDRESS, ""));
            }
            linearLayout2.addView(this.userEmail);
        }
        return linearLayout;
    }

    /* access modifiers changed from: protected */
    public void cancelNotification() {
        ((NotificationManager) getSystemService("notification")).cancel(666);
    }

    public void onClick(DialogInterface dialogInterface, int i) {
        if (i == -1) {
            sendCrash();
        } else {
            cancelReports();
        }
        finish();
    }

    private void cancelReports() {
        ACRA.getErrorReporter().deletePendingNonApprovedReports(false);
    }

    private void sendCrash() {
        EditText editText = this.userComment;
        String str = "";
        String obj = editText != null ? editText.getText().toString() : str;
        if (this.prefs != null) {
            EditText editText2 = this.userEmail;
            if (editText2 != null) {
                str = editText2.getText().toString();
                Editor edit = this.prefs.edit();
                edit.putString(ACRA.PREF_USER_EMAIL_ADDRESS, str);
                edit.commit();
            }
        }
        CrashReportPersister crashReportPersister = new CrashReportPersister(getApplicationContext());
        try {
            String str2 = ACRA.LOG_TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("Add user comment to ");
            sb.append(this.mReportFileName);
            Log.d(str2, sb.toString());
            CrashReportData load = crashReportPersister.load(this.mReportFileName);
            load.put(ReportField.USER_COMMENT, obj);
            load.put(ReportField.USER_EMAIL, str);
            crashReportPersister.store(load, this.mReportFileName);
        } catch (IOException e) {
            Log.w(ACRA.LOG_TAG, "User comment not added: ", e);
        }
        Log.v(ACRA.LOG_TAG, "About to start SenderWorker from CrashReportDialog");
        ACRA.getErrorReporter().startSendingReports(false, true);
        int resDialogOkToast = ACRA.getConfig().resDialogOkToast();
        if (resDialogOkToast != 0) {
            ToastSender.sendToast(getApplicationContext(), resDialogOkToast, 1);
        }
    }

    /* access modifiers changed from: protected */
    public void onSaveInstanceState(Bundle bundle) {
        super.onSaveInstanceState(bundle);
        EditText editText = this.userComment;
        if (!(editText == null || editText.getText() == null)) {
            bundle.putString(STATE_COMMENT, this.userComment.getText().toString());
        }
        EditText editText2 = this.userEmail;
        if (editText2 != null && editText2.getText() != null) {
            bundle.putString("email", this.userEmail.getText().toString());
        }
    }

    public void onDismiss(DialogInterface dialogInterface) {
        finish();
    }
}