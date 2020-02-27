package com.nuvent.shareat.activity.intro;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.event.UpdateEvent;
import com.nuvent.shareat.event.UpdateLaterEvent;
import com.nuvent.shareat.util.GAEvent;
import de.greenrobot.event.EventBus;

public class UpdateActivity extends BaseActivity implements OnClickListener {
    private String mCurrentVersionName;
    private String mServerVersionName;
    private String url;

    public void onBackPressed() {
        EventBus.getDefault().post(new UpdateEvent());
        finish(false);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_update);
        GAEvent.onGAScreenView(this, R.string.ga_version_chk);
        this.mCurrentVersionName = getIntent().getStringExtra("currentVersionName");
        this.mServerVersionName = getIntent().getStringExtra("serverVersionName");
        this.url = getIntent().getStringExtra("url");
        ((TextView) findViewById(R.id.current_version)).setText(getString(R.string.COMMON_VERSION_FORMAT, new Object[]{this.mCurrentVersionName}));
        ((TextView) findViewById(R.id.latest_version)).setText(getString(R.string.COMMON_VERSION_FORMAT, new Object[]{this.mServerVersionName}));
        findViewById(R.id.update).setOnClickListener(this);
        findViewById(R.id.later).setOnClickListener(this);
    }

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.later /*2131296781*/:
                EventBus.getDefault().post(new UpdateLaterEvent());
                finish(false);
                return;
            case R.id.update /*2131297462*/:
                Intent intent = new Intent("android.intent.action.VIEW");
                intent.setData(Uri.parse(this.url));
                startActivity(intent);
                EventBus.getDefault().post(new UpdateEvent());
                finish(false);
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_version_chk, (int) R.string.ga_version_chk_update, (int) R.string.ga_version_chk_label);
                return;
            default:
                return;
        }
    }
}