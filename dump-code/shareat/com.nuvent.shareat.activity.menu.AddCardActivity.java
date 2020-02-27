package com.nuvent.shareat.activity.menu;

import android.graphics.Color;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.widget.EditText;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;

public class AddCardActivity extends BaseActivity {
    private EditText birthEditor;
    private EditText cardNo1;
    private EditText cardNo2;
    private EditText cardNo3;
    private EditText cardNo4;
    private TextView mMonthHint;
    private TextView mPwHint;
    private TextView mYearHint;
    private EditText monthEditor;
    private EditText passwordEditor;
    private EditText yearEditor;

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_add_card);
        if (VERSION.SDK_INT >= 19) {
            findViewById(R.id.statusView).getLayoutParams().height = getStatusBarHeight();
        }
        this.cardNo1 = (EditText) findViewById(R.id.card_no_1);
        this.cardNo2 = (EditText) findViewById(R.id.card_no_2);
        this.cardNo3 = (EditText) findViewById(R.id.card_no_3);
        this.cardNo4 = (EditText) findViewById(R.id.card_no_4);
        this.birthEditor = (EditText) findViewById(R.id.birth);
        this.passwordEditor = (EditText) findViewById(R.id.password_editor);
        this.yearEditor = (EditText) findViewById(R.id.year_editor);
        this.monthEditor = (EditText) findViewById(R.id.month_editor);
        this.cardNo1.setNextFocusDownId(R.id.card_no_2);
        this.cardNo2.setNextFocusDownId(R.id.card_no_3);
        this.cardNo3.setNextFocusDownId(R.id.card_no_4);
        this.cardNo4.setNextFocusDownId(R.id.month_editor);
        this.monthEditor.setNextFocusDownId(R.id.year_editor);
        this.yearEditor.setNextFocusDownId(R.id.password_editor);
        this.passwordEditor.setNextFocusDownId(R.id.birth);
        this.mMonthHint = (TextView) findViewById(R.id.month_editor_hint);
        this.mYearHint = (TextView) findViewById(R.id.year_editor_hint);
        this.mPwHint = (TextView) findViewById(R.id.password_editor_hint);
        this.mMonthHint.setBackgroundColor(Color.parseColor("#7497eb"));
        this.mYearHint.setBackgroundColor(Color.parseColor("#7497eb"));
        this.mPwHint.setBackgroundColor(Color.parseColor("#7497eb"));
        this.mMonthHint.setText(R.string.month_editor_hint_text);
        this.mYearHint.setText(R.string.year_editor_hint_text);
        this.mPwHint.setText(R.string.password_editor_hint_text);
    }
}